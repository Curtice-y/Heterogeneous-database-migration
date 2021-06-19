# -*- coding: utf-8 -*-

import pymysql
import struct
from distutils.version import LooseVersion

from pymysql.constants.COMMAND import COM_BINLOG_DUMP, COM_REGISTER_SLAVE
from pymysql.cursors import DictCursor
from pymysql.util import int2byte

from streamReader.packet import BinLogPacketWrapper
from constants.BINLOG import TABLE_MAP_EVENT, ROTATE_EVENT
from streamReader.gtid import GtidSet
from streamReader.event import (
    QueryEvent, RotateEvent, FormatDescriptionEvent,
    XidEvent, GtidEvent, StopEvent,
    BeginLoadQueryEvent, ExecuteLoadQueryEvent,
    HeartbeatLogEvent, NotImplementedEvent)
from streamReader.exceptions import BinLogNotEnabled
from streamReader.row_event import (
    UpdateRowsEvent, WriteRowsEvent, DeleteRowsEvent, TableMapEvent)

try:
    from pymysql.constants.COMMAND import COM_BINLOG_DUMP_GTID
except ImportError:
    # Handle old pymysql versions
    # See: https://github.com/PyMySQL/PyMySQL/pull/261
    COM_BINLOG_DUMP_GTID = 0x1e

# 2013 Connection Lost
# 2006 MySQL server has gone away
MYSQL_EXPECTED_ERROR_CODES = [2013, 2006]


class BinLogStreamReader(object):

    """Connect to replication stream and read event
    """
    report_slave = None

    def __init__(self, connection_settings, server_id,
                 ctl_connection_settings=None, resume_stream=False,
                 blocking=False, only_events=None, log_file=None,
                 log_pos=None, filter_non_implemented_events=True,
                 ignored_events=None, auto_position=None,
                 only_tables=None, ignored_tables=None,
                 only_schemas=None, ignored_schemas=None,
                 freeze_schema=False, skip_to_timestamp=None,
                 pymysql_wrapper=None,
                 fail_on_table_metadata_unavailable=False):
        """
        Attributes:
            ctl_connection_settings: Connection settings for cluster holding
                                     schema information
            resume_stream: Start for event from position or the latest event of
                           binlog or from older available event
            blocking: When master has finished reading/sending binlog it will
                      send EOF instead of blocking connection.
            only_events: Array of allowed events
            ignored_events: Array of ignored events
            log_file: Set replication start log file
            log_pos: Set replication start log pos (resume_stream should be
                     true)
            auto_position: Use master_auto_position gtid to set position
            only_tables: An array with the tables you want to watch (only works
                         in binlog_format ROW)
            ignored_tables: An array with the tables you want to skip
            only_schemas: An array with the schemas you want to watch
            ignored_schemas: An array with the schemas you want to skip
            freeze_schema: If true do not support ALTER TABLE. It's faster.
            skip_to_timestamp: Ignore all events until reaching specified
                               timestamp.
        """

        self.__connection_settings = connection_settings
        self.__connection_settings.setdefault("charset", "utf8")

        self.__connected_stream = False
        self.__connected_ctl = False
        self.__resume_stream = resume_stream
        self.__blocking = blocking
        self._ctl_connection_settings = ctl_connection_settings
        if ctl_connection_settings:
            self._ctl_connection_settings.setdefault("charset", "utf8")

        self.__only_tables = only_tables
        self.__ignored_tables = ignored_tables
        self.__only_schemas = only_schemas
        self.__ignored_schemas = ignored_schemas
        self.__freeze_schema = freeze_schema
        self.__allowed_events = self._allowed_event_list(
            only_events, ignored_events, filter_non_implemented_events)
        #print(self.__allowed_events)
        self.__fail_on_table_metadata_unavailable = fail_on_table_metadata_unavailable

        # We can't filter on packet level TABLE_MAP and rotate event because
        # we need them for handling other operations
        self.__allowed_events_in_packet = frozenset(
            [TableMapEvent, RotateEvent]).union(self.__allowed_events)

        self.__server_id = server_id
        self.__use_checksum = False

        # Store table meta information
        self.table_map = {}
        self.log_pos = log_pos
        self.log_file = log_file
        self.auto_position = auto_position
        self.skip_to_timestamp = skip_to_timestamp


        if pymysql_wrapper:
            self.pymysql_wrapper = pymysql_wrapper
        else:
            self.pymysql_wrapper = pymysql.connect

    def close(self):
        if self.__connected_stream:
            self._stream_connection.close()
            self.__connected_stream = False
        if self.__connected_ctl:
            # break reference cycle between stream reader and underlying
            # mysql connection object
            self._ctl_connection._get_table_information = None
            self._ctl_connection.close()
            self.__connected_ctl = False

    def __connect_to_ctl(self):
        if not self._ctl_connection_settings:
            self._ctl_connection_settings = dict(self.__connection_settings)
        self._ctl_connection_settings["db"] = "information_schema"
        self._ctl_connection_settings["cursorclass"] = DictCursor
        self._ctl_connection = self.pymysql_wrapper(**self._ctl_connection_settings)
        self._ctl_connection._get_table_information = self.__get_table_information
        self.__connected_ctl = True

    def __checksum_enabled(self):
        """Return True if binlog-checksum = CRC32. Only for MySQL > 5.6"""
        cur = self._stream_connection.cursor()
        cur.execute("SHOW GLOBAL VARIABLES LIKE 'BINLOG_CHECKSUM'")
        result = cur.fetchone()
        cur.close()

        if result is None:
            return False
        var, value = result[:2]
        if value == 'NONE':
            return False
        return True


    def __connect_to_stream(self):
        # log_pos (4) -- position in the binlog-file to start the stream with
        # flags (2) BINLOG_DUMP_NON_BLOCK (0 or 1)
        # server_id (4) -- server id of this slave
        # log_file (string.EOF) -- filename of the binlog on the master
        self._stream_connection = self.pymysql_wrapper(**self.__connection_settings)

        self.__use_checksum = self.__checksum_enabled()

        # If checksum is enabled we need to inform the server about the that
        # we support it
        if self.__use_checksum:
            cur = self._stream_connection.cursor()
            cur.execute("set @master_binlog_checksum= @@global.binlog_checksum")
            cur.close()


        if not self.auto_position:
            # only when log_file and log_pos both provided, the position info is
            # valid, if not, get the current position from master
            if self.log_file is None or self.log_pos is None:
                cur = self._stream_connection.cursor()
                cur.execute("SHOW MASTER STATUS")
                master_status = cur.fetchone()
                if master_status is None:
                    raise BinLogNotEnabled()
                self.log_file, self.log_pos = master_status[:2]
                cur.close()

            prelude = struct.pack('<i', len(self.log_file) + 11) \
                + int2byte(COM_BINLOG_DUMP)

            if self.__resume_stream:
                prelude += struct.pack('<I', self.log_pos)
            else:
                prelude += struct.pack('<I', 4)

            flags = 0
            if not self.__blocking:
                flags |= 0x01  # BINLOG_DUMP_NON_BLOCK
            prelude += struct.pack('<H', flags)

            prelude += struct.pack('<I', self.__server_id)
            prelude += self.log_file.encode()
        else:

            gtid_set = GtidSet(self.auto_position)
            encoded_data_size = gtid_set.encoded_length

            header_size = (2 +  # binlog_flags
                           4 +  # server_id
                           4 +  # binlog_name_info_size
                           4 +  # empty binlog name
                           8 +  # binlog_pos_info_size
                           4)  # encoded_data_size

            prelude = b'' + struct.pack('<i', header_size + encoded_data_size)\
                + int2byte(COM_BINLOG_DUMP_GTID)

            flags = 0
            if not self.__blocking:
                flags |= 0x01  # BINLOG_DUMP_NON_BLOCK
            flags |= 0x04  # BINLOG_THROUGH_GTID

            prelude += struct.pack('<H', flags)

            # server_id (4 bytes)
            prelude += struct.pack('<I', self.__server_id)
            # binlog_name_info_size (4 bytes)
            prelude += struct.pack('<I', 3)
            # empty_binlog_name (4 bytes)
            prelude += b'\0\0\0'
            # binlog_pos_info (8 bytes)
            prelude += struct.pack('<Q', 4)

            # encoded_data_size (4 bytes)
            prelude += struct.pack('<I', gtid_set.encoded_length)
            # encoded_data
            prelude += gtid_set.encoded()

        if pymysql.__version__ < LooseVersion("0.6"):
            self._stream_connection.wfile.write(prelude)
            self._stream_connection.wfile.flush()
        else:
            self._stream_connection._write_bytes(prelude)
            self._stream_connection._next_seq_id = 1
        self.__connected_stream = True

    def fetchone(self):
        while True:
            if not self.__connected_stream:
                self.__connect_to_stream()

            if not self.__connected_ctl:
                self.__connect_to_ctl()

            try:
                if pymysql.__version__ < LooseVersion("0.6"):
                    pkt = self._stream_connection.read_packet()
                else:
                    pkt = self._stream_connection._read_packet()
            except pymysql.OperationalError as error:
                code, message = error.args
                if code in MYSQL_EXPECTED_ERROR_CODES:
                    self._stream_connection.close()
                    self.__connected_stream = False
                    continue
                raise

            if pkt.is_eof_packet():
                self.close()
                return None

            if not pkt.is_ok_packet():
                continue

            binlog_event = BinLogPacketWrapper(pkt, self.table_map,
                                               self._ctl_connection,
                                               self.__use_checksum,
                                               self.__allowed_events_in_packet,
                                               self.__only_tables,
                                               self.__ignored_tables,
                                               self.__only_schemas,
                                               self.__ignored_schemas,
                                               self.__freeze_schema,
                                               self.__fail_on_table_metadata_unavailable)

            if binlog_event.event_type == ROTATE_EVENT:
                self.log_pos = binlog_event.event.position
                self.log_file = binlog_event.event.next_binlog
                self.table_map = {}
            elif binlog_event.log_pos:
                self.log_pos = binlog_event.log_pos

            if self.skip_to_timestamp and binlog_event.timestamp < self.skip_to_timestamp:
                continue

            if binlog_event.event_type == TABLE_MAP_EVENT and \
                    binlog_event.event is not None:
                self.table_map[binlog_event.event.table_id] = \
                    binlog_event.event.get_table()

            # event is none if we have filter it on packet level
            # we filter also not allowed events
            if binlog_event.event is None or (binlog_event.event.__class__ not in self.__allowed_events):
                continue

            return binlog_event.event

    def _allowed_event_list(self, only_events, ignored_events,
                            filter_non_implemented_events):
        if only_events is not None:
            events = set(only_events)
        else:
            events = {QueryEvent, RotateEvent, StopEvent, FormatDescriptionEvent, XidEvent, GtidEvent,
                      BeginLoadQueryEvent, ExecuteLoadQueryEvent, UpdateRowsEvent, WriteRowsEvent, DeleteRowsEvent,
                      TableMapEvent, HeartbeatLogEvent, NotImplementedEvent}
        if ignored_events is not None:
            for e in ignored_events:
                events.remove(e)
        if filter_non_implemented_events:
            try:
                events.remove(NotImplementedEvent)
            except KeyError:
                pass
        return frozenset(events)

    def __get_table_information(self, schema, table):
        for i in range(1, 3):
            try:
                if not self.__connected_ctl:
                    self.__connect_to_ctl()

                cur = self._ctl_connection.cursor()
                cur.execute("""
                    SELECT
                        COLUMN_NAME, COLLATION_NAME, CHARACTER_SET_NAME,
                        COLUMN_COMMENT, COLUMN_TYPE, COLUMN_KEY, ORDINAL_POSITION
                    FROM
                        information_schema.columns
                    WHERE
                        table_schema = %s AND table_name = %s
                    ORDER BY ORDINAL_POSITION
                    """, (schema, table))

                return cur.fetchall()
            except pymysql.OperationalError as error:
                code, message = error.args
                if code in MYSQL_EXPECTED_ERROR_CODES:
                    self.__connected_ctl = False
                    continue
                else:
                    raise error

    def __iter__(self):
        return iter(self.fetchone, None)
