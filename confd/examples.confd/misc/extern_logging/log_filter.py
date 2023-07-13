#!/usr/bin/env python3

import re
import sys
import xml.etree.ElementTree


class LogInfo(object):
    """Log stream information"""

    def __init__(self, argv):
        self.id = argv[0]
        self.type = argv[1]
        self.format = argv[2]


class TraceParser(object):
    re_write = re.compile(r'^\*\*< sess:([0-9]+) write:')

    def __init__(self):
        self._sessions = {}
        self._sess = None

    def feed(self, line):
        if line == 'END OF MESSAGE\n':
            return self._end_op()

        # write data
        match = self.re_write.match(line)
        if match is not None:
            sess = match.group(1)
            if sess not in self._sessions:
                self._sessions[sess] = []
            self._sess = sess
        # other operation, stop write data
        elif line.startswith('**>') or line.startswith('**<'):
            self._sess = None
        elif self._sess is not None:
            self._sessions[self._sess].append(line)
            return True
        return False

    def _end_op(self):
        sess = self._sess
        self._sess = None

        if sess is None:
            return False

        lines = self._sessions[sess]
        del self._sessions[sess]
        if lines:
            return ''.join(lines)
        else:
            return False


def main():
    if len(sys.argv) != 6:
        usage()
    elif sys.argv[1] != '1':
        abort('unsupported version {}, version 1 supported'.format(
            sys.argv[1]))
    elif sys.argv[2] != 'log':
        abort('unsupported command {}, command log supported'.format(
            sys.argv[1]))

    log_info = LogInfo(sys.argv[3:])
    process_log_data(log_info)


def usage():
    abort('usage: {} version command log-id log-type log-format'.format(
        sys.argv[0]))


def abort(msg):
    sys.stderr.write(msg)
    sys.stderr.write('\n')
    sys.exit(1)


def process_log_data(log_info):
    # only filter data for raw netconf-trace data, send all other log
    # data to the void.
    if log_info.type == 'netconf-trace' and log_info.format == 'raw':
        process_netconf_trace(log_info)
    else:
        process_generic_log(log_info)


def process_netconf_trace(log_info):
    trace_parser = TraceParser()

    with open('netconf_filtered.trace', 'a') as f_obj:
        line = sys.stdin.readline()
        while line:
            res = trace_parser.feed(line)
            if res is True:
                # buffered data
                pass
            elif res is False:
                f_obj.write(line)
            else:
                filtered_xml = filter_netconf_trace_msg(res)
                f_obj.write(filtered_xml)
                f_obj.write(line)
            f_obj.flush()

            line = sys.stdin.readline()


def filter_netconf_trace_msg(msg):
    doc = xml.etree.ElementTree.fromstring(msg)
    secrets = doc.findall(".//{urn:example:secret_model}address")
    if not secrets:
        return msg

    for tag in secrets:
        tag.text = '********'
    return '{}\n'.format(xml.etree.ElementTree.tostring(doc))


def process_generic_log(log_info):
    # just read and discard input
    for line in sys.stdin:
        pass


if __name__ == '__main__':
    main()
