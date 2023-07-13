import sys
import confd.maapi


def main():
    if len(sys.argv) != 3:
        usage()

    if sys.argv[1] == 'get_next':
        fun = test_get_next
        path = sys.argv[2]
    elif sys.argv[1] == 'find_next':
        fun = test_find_next
        path = sys.argv[2]
    elif sys.argv[1] == 'get_next_object':
        fun = test_get_next_object
        path = sys.argv[2]
    elif sys.argv[1] == 'find_next_object':
        fun = test_find_next_object
        path = sys.argv[2]
    else:
        usage()

    with confd.maapi.single_read_trans('admin', 'system') as tr:
        fun(tr, path)


def usage():
    sys.stderr.write(
        'usage: {} [get_next|get_next_object]\n'.format(sys.argv[0]))
    sys.exit(1)


def test_get_next(tr, path):
    cursors = {'c1': tr.cursor(path),
               'c2': tr.cursor(path),
               'c3': tr.cursor(path)}

    print('press enter to get next cursor values')

    i = 0
    done = False
    while not done:
        i += 1
        sys.stdin.readline()
        done = print_next(i, cursors)

    print('iteration complete, stopping')


def print_next(i, cursors):
    done = True

    print('iteration {}'.format(i))
    for name in sorted(cursors.keys()):
        try:
            value = next(cursors[name])
            done = False
        except StopIteration:
            value = None
        print('{}: {}'.format(name, value))

    return done


def test_find_next(tr, path):
    cursors = {'c1': tr.cursor(path),
               'c2': tr.cursor(path),
               'c3': tr.cursor(path)}

    for (name, key) in (('c1', 'one'), ('c2', 'two'), ('c3', 'three')):
        keys = tr.maapi.find_next(
            cursors[name].cur, confd.FIND_NEXT, [confd.Value(key)])
        print('{} initial keys {}'.format(name, keys))
        if not keys:
            cursors[name] = None

    print('press enter to get next cursor values')

    i = 0
    done = False
    while not done:
        i += 1
        sys.stdin.readline()
        done = print_find_next(i, cursors)

    print('iteration complete, stopping')


def print_find_next(i, cursors):
    print('iteration {}'.format(i))
    for name in sorted(cursors.keys()):
        if cursors[name] is None:
            value = None
        else:
            try:
                value = next(cursors[name])
            except StopIteration:
                cursors[name] = None
                value = None
        print('{}: {}'.format(name, value))

    return not any(cursors.values())


def test_get_next_object(tr, path):
    cursors = {'c1': tr.cursor(path),
               'c2': tr.cursor(path),
               'c3': tr.cursor(path)}

    print('press enter to get next cursor values')

    i = 0
    done = False
    while not done:
        i += 1
        sys.stdin.readline()
        done = print_next_object(tr, i, cursors)

    print('iteration complete, stopping')


def print_next_object(tr, i, cursors):
    done = True

    print('iteration {}'.format(i))
    for name in sorted(cursors.keys()):
        objects = tr.maapi.get_objects(cursors[name].cur, 8, 1)
        done = objects == []
        print('{}'.format(name))
        for obj in objects:
            for value in obj:
                print('  - {}'.format(value))

    return done


def test_find_next_object(tr, path):
    cursors = {'c1': tr.cursor(path),
               'c2': tr.cursor(path),
               'c3': tr.cursor(path)}

    for (name, key) in (('c1', 'one'), ('c2', 'two'), ('c3', 'three')):
        keys = tr.maapi.find_next(
            cursors[name].cur, confd.FIND_NEXT, [confd.Value(key)])
        print('{} initial keys {}'.format(name, keys))
        if not keys:
            cursors[name] = None

    print('press enter to get next cursor values')

    i = 0
    done = False
    while not done:
        i += 1
        sys.stdin.readline()
        done = print_find_next_object(tr, i, cursors)

    print('iteration complete, stopping')


def print_find_next_object(tr, i, cursors):
    print('iteration {}'.format(i))
    for name in sorted(cursors.keys()):
        if cursors[name] is None:
            objects = []
        else:
            objects = tr.maapi.get_objects(cursors[name].cur, 8, 1)
            if len(objects) == 0:
                cursors[name] = None

        print('{}'.format(name))
        for obj in objects:
            for value in obj:
                print('  - {}'.format(value))

    return not any(cursors.values())


if __name__ == '__main__':
    main()
