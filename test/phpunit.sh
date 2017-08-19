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
    if [ -f phpunit-6.3.0.phar ]; then
        rm -f phpunit-6.3.0.phar
    fi
    if [ -f phpunit-6.3.0.phar.asc ]; then
        rm -f phpunit-6.3.0.phar.asc
    fi
fi

# Let's grab the latest release and its signature
if [ ! -f phpunit-6.3.0.phar ]; then
    wget https://phar.phpunit.de/phpunit-6.3.0.phar
    if [ $? -ne 0 ]; then
        echo "wget phpunit-6.3.0.phar was unsuccessful"
        exit 1
    fi
fi
if [ ! -f phpunit-6.3.0.phar.asc ]; then
    wget https://phar.phpunit.de/phpunit-6.3.0.phar.asc
    if [ $? -ne 0 ]; then
        echo "wget phpunit-6.3.0.phar.asc was unsuccessful"
        exit 1
    fi
fi

# Verify before running
gpg --batch --verify phpunit-6.3.0.phar.asc phpunit-6.3.0.phar >& phpunit.out2
if [ $? -eq 0 ]; then
    echo
    echo -e "\033[33mBegin Unit Testing\033[0m"
    # Run the testing suite
    php phpunit-6.3.0.phar --bootstrap "$parentdir/autoload.php" "$parentdir/test/unit"
    EXITCODE=$?
    # Test with mbstring.func_overload = 7
    php -dmbstring.func_overload=7 phpunit-6.3.0.phar --bootstrap "$parentdir/autoload.php" "$parentdir/test/unit"
    # Cleanup
    if [ "$clean" -eq 1 ]; then
        echo -e "\033[32mCleaning Up!\033[0m"
        rm -f phpunit-6.3.0.phar
        rm -f phpunit-6.3.0.phar.asc
        rm -f phpunit.out
        rm -f phpunit.out2
    fi
    exit ${EXITCODE}
else
    echo
    chmod -x phpunit-6.3.0.phar
    mv phpunit-6.3.0.phar /tmp/bad-phpunit-6.3.0.phar
    mv phpunit-6.3.0.phar.asc /tmp/bad-phpunit-6.3.0.phar.asc
    cat phpunit.out2
    echo -e "\033[31mSignature did not match! Check /tmp/bad-phpunit-6.3.0.phar for trojans\033[0m"
    exit 1
fi
