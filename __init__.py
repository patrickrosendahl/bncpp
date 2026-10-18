try:
    from .cpp import pseudo_cpp
    pseudo_cpp.register()
    from .constants import LANGUAGE_NAME
    from .cpp import landing_pads
    landing_pads.register_command(LANGUAGE_NAME)
    from .cpp import eh_path
    eh_path.register_command(LANGUAGE_NAME)
    from .shared import bncache
    bncache.install_save_hook()
except Exception:  # the language is optional; never break Binary Ninja's startup
    import traceback
    traceback.print_exc()
