#!/usr/bin/env bash

origdir=`pwd`
cdir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd ${origdir}
parentdir="$(dirname ${cdir})"

clean=0 # Clean up?
gpg --fingerprint D8406D0D82947747293778314AA394086372C20A >& phpunit.out
if [ $? -ne 0 ]; then
    echo -e "\033[33mDownloading PGP Public Key...\033[0m"
    gpg  --keyserver pgp.mit.edu --recv-keys D8406D0D82947747293778314AA394086372C20A
    # Sebastian Bergmann <sb@sebastian-bergmann.de>
    gpg --fingerprint D8406D0D82947747293778314AA394086372C20A
    if [ $? -ne 0 ]; then
        echo -e "\033[31mCould not download PGP public key for verification\033[0m"
        exit 1
    fi
else
    cat phpunit.out
fi

if [ "$clean" -eq 1 ]; then
    # Let's clean them up, if they exist
    if [ -f phpunit.phar ]; then
        rm -f phpunit.phar
    fi
    if [ -f phpunit.phar.asc ]; then
        rm -f phpunit.phar.asc
    fi
fi

# Let's grab the latest release and its signature
if [ ! -f phpunit.phar ]; then
    wget https://phar.phpunit.de/phpunit.phar
    if [ $? -ne 0 ]; then
        echo "wget phpunit.phar was unsuccessful"
        exit 1
    fi
fi
if [ ! -f phpunit.phar.asc ]; then
    wget https://phar.phpunit.de/phpunit.phar.asc
    if [ $? -ne 0 ]; then
        echo "wget phpunit.phar.asc was unsuccessful"
        exit 1
    fi
fi

# Verify before running
gpg --batch --verify phpunit.phar.asc phpunit.phar >& phpunit.out2
if [ $? -eq 0 ]; then
    echo
    echo -e "\033[33mBegin Unit Testing\033[0m"
    # Run the testing suite
    php phpunit.phar --bootstrap "$parentdir/autoload.php" "$parentdir/test/unit"
    EXITCODE=$?
    # Cleanup
    if [ "$clean" -eq 1 ]; then
        echo -e "\033[32mCleaning Up!\033[0m"
        rm -f phpunit.phar
        rm -f phpunit.phar.asc
        rm -f phpunit.out
        rm -f phpunit.out2
    fi
    exit ${EXITCODE}
else
    echo
    chmod -x phpunit.phar
    mv phpunit.phar /tmp/bad-phpunit.phar
    mv phpunit.phar.asc /tmp/bad-phpunit.phar.asc
    cat phpunit.out2
    echo -e "\033[31mSignature did not match! Check /tmp/bad-phpunit.phar for trojans\033[0m"
    exit 1
fi
