from setuptools import setup, find_packages

setup(
    name="http-smuggler",
    version="1.0.0",
    description="HTTP Request Smuggling Vulnerability Scanner for Bug Bounty & Pentesting",
    author="HTTP Smuggler",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "urllib3>=2.0.0",
        "rich>=13.7.0",
        "click>=8.1.7",
        "pyyaml>=6.0.1",
        "httpx[http2]>=0.27.0",
        "jinja2>=3.1.3",
        "colorama>=0.4.6",
        "tqdm>=4.66.0",
        "python-dateutil>=2.9.0",
    ],
    extras_require={
        "pdf": ["weasyprint>=61.2"],
    },
    entry_points={
        "console_scripts": [
            "smuggler=main:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
