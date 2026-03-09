from setuptools import setup, find_packages

setup(
    name="sentinel-core",
    version="2.0.0",
    author="Sentinel Security",
    author_email="support@sentinel.security",
    description="Deterministic Security Gate for CI/CD, IaC, and Supply Chain Integrity",
    long_description="A professional security tool designed to enforce policies in automated pipelines.",
    long_description_content_type="text/markdown",
    url="https://github.com/<YOUR_ORGANIZATION_OR_USERNAME> # FIXME: Replace with your actual GitHub Org/User/<YOUR_PRIVATE_REPO_NAME>",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.so", "*.pyd", "*.py"],
        "sentinel": ["*.yaml", "rules/**/*.py"],
    },
    install_requires=[
        "click==8.1.7",
        "pyyaml==6.0.1",
        "requests",
        "openai",
        "python-dotenv",
        "pdfkit",
    ],
    entry_points={
        "console_scripts": [
            "sentinel=sentinel.main:cli",
        ],
    },
    python_requires=">=3.10",
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)