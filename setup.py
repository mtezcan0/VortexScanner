from setuptools import setup, find_packages

setup(
    name='vortexscan',
    version='1.1.0',
    description='Advanced Async Web Reconnaissance Tool',
    author='Mehmet Tezcan',
    py_modules=['main'],  
    packages=find_packages(),  
    install_requires=[
        'aiohttp>=3.9.0',
        'aiodns>=3.1.0',
        'beautifulsoup4>=4.12.0',
        'colorama>=0.4.6',
        'lxml>=5.1.0'
        
    ],
    entry_points={
        'console_scripts': [
            
            'vortexscan=main:run_main',
        ],
    },
)