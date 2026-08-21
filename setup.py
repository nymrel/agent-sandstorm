from setuptools import setup, find_packages

setup(
    name="agent-sandstorm",
    version="1.0.0",
    description="Zero-Trust Agent Execution Sandbox & Copy-on-Write Workspace Isolation Engine",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Nymrel",
    author_email="contact@nymrel.com",
    url="https://github.com/nymrel/agent-sandstorm",
    package_dir={"": "python"},
    packages=find_packages(where="python"),
    python_requires=">=3.9",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "sandstorm-py = agent_sandstorm.cli:main",
        ],
    },
)
