from setuptools import setup, find_packages

setup(
    name='vortexscan',
    version='1.0.0',
    py_modules=['main'],
    packages=find_packages(),
    install_requires=[
        'requests',
        'beautifulsoup4',
        'colorama',
        'pyfiglet',
        'validators',
        'lxml'
    ],
    entry_points={
        'console_scripts': [
            'vortexscan=main:main',
        ],
    },
)