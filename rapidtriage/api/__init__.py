__all__ = ["app", "create_app"]


def __getattr__(name: str):
    if name not in __all__:
        raise AttributeError(name)
    try:
        from .app import app, create_app
    except ModuleNotFoundError as exc:
        if exc.name == "fastapi":
            raise ModuleNotFoundError(
                "rapidtriage.api requires the optional 'fastapi' web dependency. "
                "Install the web extra before importing API objects."
            ) from exc
        raise
    return {"app": app, "create_app": create_app}[name]
