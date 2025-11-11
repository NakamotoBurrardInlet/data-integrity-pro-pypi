from setuptools import setup, find_packages

# Define dependencies (we will use the industry-standard 'cryptography' library)
INSTALL_REQUIRES = [
    'cryptography>=41.0.3', 
    'colorama>=0.4.6' # For colored terminal output in logging/usage
]

setup(
    name='data-integrity-pro',
    version='1.0.0',
    description='A high-performance Python package for cryptographic data integrity verification and symmetric encryption.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Professional Security Developer',
    author_email='mrsatoshinakamotoofburrardst@gmail.com',
    url='https://github.com/NakamotoBurrardInlet/data-integrity-pro-pypi',
    packages=find_packages(),
    install_requires=INSTALL_REQUIRES,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    keywords='security encryption data-integrity sha256 aes',
    python_requires='>=3.8',
)