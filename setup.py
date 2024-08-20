from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="nc_tokens",
    version="0.0.1",
    author="Neural Coders - Jorge Zapata",
    author_email="jorge.zapata@neuralcoders.com",
    description="Create service and user tokens for microservices",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/NeuralCoders/nc_tokens",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "cryptography>=3.4.7",
        "boto3>=1.17.0",
        "cffi==1.16.0",
        "pycparser==2.22",
        "botocore~=1.35.1"
    ],
)
