import setuptools


setuptools.setup(name='matasano-crypto-solutions',
                 version='0.0.0',
                 description='My attempt at solving the Cryptopals.com '
                 'challenges',
                 long_description=open('README.md').read().strip(),
                 author='Ismail S',
                 author_email='ismail-s.no-reply@github.com',
                 url='https://github.com/ismail-s/Matasano-Crypto-Solutions',
                 py_modules=['matasano_crypto_solutions'],
                 install_requires=open('requirements.txt').read().split(),
                 setup_requires=['pytest-runner'],
                 tests_require=['pytest', 'pytest-flake8', 'pytest-cov'],
                 license='MIT License',
                 zip_safe=True)
