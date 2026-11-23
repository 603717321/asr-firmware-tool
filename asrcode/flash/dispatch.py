"""Shared worker routing for source and frozen entry points."""
import runpy,sys
def dispatch(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    args=[a for a in args if a not in ('-X','utf8','-u')]
    if len(args)<2 or args[0]!='-m':return False
    name=args[1]
    if name not in ('asrcode.flash.at_flash_backup','asrcode.flash.direct_flash'):
        raise ValueError('未知读写后台入口：'+name)
    from asrcode.flash.worker_encoding import configure_worker_streams
    configure_worker_streams()
    sys.argv=[name]+args[2:]
    runpy.run_module(name,run_name='__main__')
    return True
