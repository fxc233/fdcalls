from setuptools import setup, find_packages

setup(name='fdcalls',
    version='1.2',
    description='help view dangerous function calls across files',
    author='fxc',
    author_email='FXC030618@outlook.com',
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        'r2pipe>=1.8.0',
    ],
    entry_points={
        'console_scripts': [
            'fdcalls=fdcalls.fdcalls:main'
        ]
    }
)
