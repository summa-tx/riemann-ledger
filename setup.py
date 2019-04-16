from setuptools import setup, find_packages

setup(
    name='riemann-ledger',
    version='0.0.2',
    description=('Sign Bitcoin transactions on your Ledger Nano S'),
    author=["James Prestwich"],
    license="LGPLv3.0",
    install_requires=[
        'ledgerblue',
        'riemann-tx',
        'mypy-extensions'],
    packages=find_packages(),
    package_data={'ledger': ['py.typed']},
    package_dir={'ledger': 'ledger'},
    python_requires='>=3.6'
)
