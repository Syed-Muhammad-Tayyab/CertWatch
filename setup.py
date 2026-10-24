from setuptools import setup, find_packages

setup(
    name="certwatch",
    version="1.0.0",
    description="Audit a host's TLS/SSL certificate for expiry, weak protocols, and misconfigurations.",
    author="Syed Muhammad Tayyab",
    url="https://github.com/Syed-Muhammad-Tayyab/CertWatch",
    packages=find_packages(),
    install_requires=["cryptography>=42.0.0"],
    entry_points={
        "console_scripts": [
            "certwatch=certwatch.cli:main",
        ],
    },
    python_requires=">=3.9",
)
