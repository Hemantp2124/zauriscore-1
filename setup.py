import os
from setuptools import setup, find_packages

def read_requirements(filename):
    """Read requirements from a file, handling -r references."""
    requirements = []
    if not os.path.exists(os.path.join('requirements', filename)):
        return requirements
        
    with open(os.path.join('requirements', filename)) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                if line.startswith('-r '):
                    # Handle requirement file references
                    requirements.extend(read_requirements(line.split(' ')[1]))
                else:
                    requirements.append(line)
    return requirements

# Read requirements
base_reqs = read_requirements('base.txt')
dev_reqs = [r for r in read_requirements('dev.txt') if r not in base_reqs]
prod_reqs = [r for r in read_requirements('prod.txt') if r not in base_reqs]

setup(
    name="zauriscore",
    version="1.0.0",
    description="AI-powered smart contract security analysis platform",
    # Read README with a context manager
    long_description=(
        (lambda p: (open(p, encoding='utf-8').read() if os.path.exists(p) else ""))('README.md')
    ),
    long_description_content_type='text/markdown',
    author="ZauriScore Team",
    author_email="team@zauriscore.com",
    url="https://github.com/zauriscore/zauriscore",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=base_reqs,
    extras_require={
        'dev': dev_reqs,
        'prod': prod_reqs,
        'all': list(set(dev_reqs + prod_reqs))
    },
    entry_points={
        "console_scripts": [
            "smart-contract-security=smart_contract_security.cli.main:main",
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    keywords='ethereum smart-contract security analysis ml',
    include_package_data=True,
    zip_safe=False,
)