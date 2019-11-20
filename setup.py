# flake8: noqa

from setuptools import setup, find_packages

reqs = [
    'ledgerblue==0.1.23',
    'riemann-tx==2.1.0',
    'mypy-extensions'
]

setup(
    name='riemann-ledger',
    version='0.1.0',
    url='https://github.com/summa-tx/riemann-ledger',
    description=('Sign Segwit Bitcoin transactions on your Ledger Nano S'),
    author=["James Prestwich"],
    author_email='james@summa.one',
    install_requires=reqs,
    packages=find_packages(),
    package_dir={'ledger': 'ledger'},
    package_data={'ledger': ['py.typed']},
    python_requires='>=3.6',
    classifiers=[
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)'
    ]
)
