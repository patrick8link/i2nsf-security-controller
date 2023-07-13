import distutils.core
import distutils.sysconfig
import os
import sys

def get_flag(flag, str_args):
    for arg in str_args.split(' '):
        if arg.startswith(flag):
            return arg
    return None

def get_fortify_flag(str_args):
    return get_flag('-D_FORTIFY_SOURCE', str_args)

def get_optimize_flag(str_args):
    return get_flag('-O', str_args)

top_dir = os.path.expandvars('${TOP_DIR}')
top_dir_include = os.path.join(top_dir, 'include')
top_dir_lib = os.path.join(top_dir, 'lib')

if (os.path.exists(top_dir_include) is not True):
    print("Something wrong with TOP_DIR, can't find: ", top_dir_include)
    sys.exit(1)

mod_name = os.path.expandvars('${PROD}')
lmod_name = '_' + mod_name.lower()
umod_name = mod_name.upper()
cmod_name = lmod_name + '_' + os.path.expandvars('${PYVER}')

srcs = os.path.expandvars('${SRC}').split()
deps = list(srcs)
deps.extend(os.path.expandvars('${INC}').split())

if os.environ.get('RTPATH'):
    rtpath = ['$ORIGIN/' + os.path.expandvars('${RTPATH}')]
else:
    rtpath = None

extra_compile_args = ['-std=c99']
py_cppflags = distutils.sysconfig.get_config_vars().get('PY_CPPFLAGS', '')
cbase_flags = os.environ.get('CBASE_FLAGS', '')

if get_fortify_flag(py_cppflags) is None:
    # fortify not provided by the system, check if it is in
    # CBASE_FLAGS and use if there
    fortify_flag = get_fortify_flag(cbase_flags)
    if fortify_flag is not None:
        extra_compile_args.append(fortify_flag)

# Since FORTIFY_SOURCE is set no matter the base CFLAGS - do it right
# FORTIFY_SOURCE requires at least O1 since Glibc 2.16
if sys.platform == 'linux':
    opt_flag = get_optimize_flag(cbase_flags)
    if not opt_flag:
        extra_compile_args.append('-O1')
    else:
        extra_compile_args.append(opt_flag)

# Note 1: The MacOS 10.5 Python installation builds universal binaries
#         by default, which will produce the "file is not of required
#         architecture" warning since libconfd isn't built as a
#         universal binary. It is safe to ignore this warning (or set
#         ARCHFLAGS to "").
#
# Note 2: As it is setup most systems will prefer to link against the
#         dynamic library libconfd.so in confd_dir_lib. This means
#         that when you try to use confd_api.so you must have
#         confd_dir_lib in your {DY,}LD_LIBRARY_PATH

define_macros = [('CONFD_PY_PRODUCT_%s' % (umod_name), 1),
                 ('CONFD_C_PRODUCT_%s' % (umod_name), 1),
                 ('_TM', '"%s"' % (lmod_name, ))]
if sys.platform == 'linux':
    define_macros.append(('HAVE_SYS_PRCTL_H', 1))

if os.getenv('CONFD_PY_EXT_API_TIMING') is not None:
    define_macros.append(('CONFD_PY_EXT_API_TIMING', '1'))


module = distutils.core.Extension(
    '%s.%s' % (lmod_name, cmod_name),
    include_dirs=[top_dir_include, 'include'],
    libraries=['confd'],
    library_dirs=[top_dir_lib],
    define_macros=define_macros,
    undef_macros=['NDEBUG'],
    extra_compile_args=extra_compile_args,
    sources=srcs,
    depends=deps,
    runtime_library_dirs=rtpath)

distutils.core.setup(
    name=cmod_name,
    version='1.0',
    description=mod_name + ' low-level library bindings for Python',
    long_description=mod_name + ' low-level library bindings for Python',
    author='Tail-f Systems',
    author_email='info@tail-f.com',
    url='http://www.tail-f.com/',
    packages=[lmod_name],
    ext_modules=[module])
