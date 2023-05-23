from setuptools import setup, find_packages

setup(
    name='CRM',
    version='1.0.0',
    description='A sample Python package',
    author='Onur Kavrık',
    author_email='kavrik.onur@gmail.com',
    packages=find_packages(),
    install_requires=[
        'dependency1',
        'dependency2',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.11',
    ],
)
