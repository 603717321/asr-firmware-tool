"""Boolean flag pairs supported by Python 3.8 and newer."""

def add_boolean_option(parser, option, *, default):
    dest = option[2:].replace('-', '_')
    parser.add_argument(option, dest=dest, action='store_true', default=default)
    parser.add_argument('--no-'+option[2:], dest=dest, action='store_false')
