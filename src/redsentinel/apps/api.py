"""Public FastAPI application factory.

FastAPI remains optional; importing the research core does not import this
module or require product dependencies.
"""

from redsentinel.application.engine.app import create_app

__all__ = ["create_app"]
