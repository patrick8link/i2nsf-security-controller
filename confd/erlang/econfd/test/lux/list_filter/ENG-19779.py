import sys
import confd.maapi


def main():
    if len(sys.argv) != 4:
        usage()

    if sys.argv[1] == 'get_next':
        fun = test_get_next
        path = sys.argv[2]
        xpath_expr = sys.argv[3] != 'None' and sys.argv[3] or None
    elif sys.argv[1] == 'get_next_object':
        fun = test_get_next_object
        path = sys.argv[2]
        xpath_expr = sys.argv[3] != 'None' and sys.argv[3] or None
    elif sys.argv[1] == 'filter':
        fun = test_filter
        path = sys.argv[2]
        xpath_expr = sys.argv[3]
    else:
        usage()

    with confd.maapi.single_read_trans('admin', 'system') as tr:
        fun(tr, path, xpath_expr)


def usage():
    sys.stderr.write(
        'usage: {} [get_next|get_next_object|filter] xpath_expr\n'.format(
            sys.argv[0]))
    sys.exit(1)


def test_get_next(tr, path, xpath_expr):
    cur = tr.cursor(path, xpath_expr=xpath_expr)

    print('press enter to get next cursor values')

    i = 0
    done = False
    while not done:
        i += 1
        sys.stdin.readline()
        try:
            value = next(cur)
            print('{} {}'.format(i, value))
        except StopIteration:
            done = True

    print('iteration complete, stopping')


def test_get_next_object(tr, path, xpath_expr):
    cur = tr.cursor(path, xpath_expr=xpath_expr)

    print('press enter to get next cursor values')

    i = 0
    done = False
    while not done:
        i += 1
        sys.stdin.readline()

        objects = tr.maapi.get_objects(cur.cur, 8, 1)
        done = objects == []
        print('{}'.format(i))
        for obj in objects:
            for value in obj:
                print('  - {}'.format(value))

    print('iteration complete, stopping')


def test_filter(tr, path, xpath_expr):
    cur = tr.cursor(path, xpath_expr=xpath_expr)
    try:
        value = next(cur)
        print('path {} filter {} first value {}'.format(
            path, xpath_expr, value))
    except StopIteration:
        print('path {} filter {} NO value'.format(path, xpath_expr))


if __name__ == '__main__':
    main()
