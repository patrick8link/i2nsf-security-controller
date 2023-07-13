"""
Wrapper around our custom pdoc to generate API documentation.
Usage: generate.py -- <MODULE> [<MODULE> ...]
"""

import pdoc.cli as cli
import custom_pdoc as pdoc
import os.path as path
import sys
import typing_extensions


def process(modules, outdir):
    # Reference the original templates
    pdoc_dir = path.dirname(cli.__file__)
    pdoc.tpl_lookup.directories.append(path.join(pdoc_dir, 'templates'))

    context = pdoc.Context()
    pmodules = [pdoc.Module(mod, context=context) for mod in modules]
    pdoc.link_inheritance(context)

    # C code does not do the 'import ...' statements, so we need to manually
    # setup the right references to make linking and types work
    pdoc.custom_globals.update(typing_extensions.__dict__)
    for m in pmodules:
        if m.name == '_confd' or m.name == '_ncs':
            pdoc.custom_globals[m.name] = m.obj

    # Process all modules
    cli.args.output_dir = outdir
    for m in pmodules:
        cli.recursive_write_files(m, ext='.html')

    # If we have more than a single module, also generate index.html
    if len(modules) > 1:
        with open(path.join(outdir, 'index.html'), 'w') as f:
            f.write(pdoc._render_template('/html.mako',
                modules=[(m.refname, m.docstring) for m in pmodules]))


def main():
    modules = []
    if '--' in sys.argv:
        while len(sys.argv) and sys.argv[-1] != '--':
            modules.append(sys.argv.pop())
    modules.reverse()

    if not len(modules):
        raise ValueError('No modules specified')

    # Use the first specified module as output dir
    process(modules, modules[0])


if __name__ == '__main__':
    main()
