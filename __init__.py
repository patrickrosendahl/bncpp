try:
    from .cpp import pseudo_cpp
    pseudo_cpp.register()
    from .shared import bncache
    bncache.install_save_hook()
except Exception:  # the language is optional; never break Binary Ninja's startup
    import traceback
    traceback.print_exc()
