import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dnssec-scanner-fabian-hk",  # Replace with your own username
    version="0.0.0",
    author="Fabian Hauck",
    author_email="hauckfabian@gmail.com",
    description="DNSSEC scanner with detailed error messages.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fabian-hk/dnssec_scanner.git",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "dnspython",
        "tabulate",
        "dataclasses",
        "pycryptodome",
        "requests",
    ],
)
