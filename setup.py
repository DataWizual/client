from setuptools import setup, find_packages

setup(
    name="sentinel-core",
    version="2.1.0",
    author="DataWizual Security",
    author_email="eldorzufarov66@gmail.com",
    description="Deterministic Security Gate with AI-powered audit engine",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/datawizual/sentinel-core",
    # find_packages() автоматически найдёт sentinel/ и auditor/
    # так как оба содержат __init__.py
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "sentinel": [
            "*.yaml",
            "*.json",
            "rules/**/*.py",
        ],
        "auditor": [
            "resources/*.json",
            "resources/*.yaml",
            "rules/*.yaml",
        ],
    },
    install_requires=[
        "click==8.1.7",
        "pyyaml==6.0.1",
        "requests==2.31.0",
        "python-dotenv==1.0.0",
        "pydantic>=2.5.3",
        "pydantic-settings>=2.1.0",
        "cryptography>=42.0.0",
        "jinja2>=3.1.3",
        "python-magic>=0.4.27",
        "httpx>=0.26.0",
        "openai==2.15.0",
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