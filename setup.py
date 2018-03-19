import sys
sys.path.pop(0)
from setuptools import setup

setup(
    name="pybranca",
    py_modules=["branca", "xchacha20poly1305"],
    version="0.1.0",
    description="Authenticated and encrypted API tokens using modern crypto",
    long_description="Branca is a secure easy to use token format which makes it hard to shoot yourself in the foot. It uses IETF XChaCha20-Poly1305 AEAD symmetric encryption to create encrypted and tamperproof tokens. The enrypted token is base62 encoded which makes it URL safe. Payload itself is an arbitrary sequence of bytes.",
    keywords="api, token, jwt, xchacha20, poly1305",
    url="https://github.com/tuupola/branca-python",
    author="Mika Tuupola",
    author_email="tuupola@appelsiini.net",
    maintainer="Mika Tuupola",
    maintainer_email="tuupola@appelsiini.net",
    license="MIT",
    install_requires=[
        "pybase62>=0.3"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
    ],
)
