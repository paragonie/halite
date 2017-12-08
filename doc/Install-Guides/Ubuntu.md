# Installing Halite on Ubuntu 16.04 and newer

Assuming that you don't have build utils, php7 devtools, git, pear&pecl, composer (fresh install)

## Libsodium
1. Get build utils
   `sudo apt-get install build-essential`
2. Get php7.0-dev
   `sudo apt-get install php7.0-dev`
    *Or php7.1-dev/php7.2-dev*
    `sudo apt-get install php7.1-dev`
    `sudo apt-get install php7.2-dev`
3. Git (good)
   `sudo apt-get install git`
4. Get libsodium

```
# Clone the libsodium source tree & Build libsodium, perform any defined tests, install libsodium
git clone -b stable https://github.com/jedisct1/libsodium.git && cd libsodium && ./configure && make check && make install
```
1. Get PEAR & PECL
   `sudo apt-get install pear`
2. Install libsodium from PECL
   `pecl install libsodium` (*or `pecl install -f libsodium-2.0.8` according to comments*)
3. Get straight to **/etc/php/<PHP_VERSION>/mods-available/** and make a `libsodium.ini` file (*Where <PHP_VERSION> is 7.0 or 7.1 or 7.2*)
4. Write down `extension=libsodium.so` (*or `sodium.so` according to comments*) in `libsodium.ini` & save (**Yes, it works like this now**, no more php.ini bs)
5. Enable the libsodium mod
`sudo phpenmod libsodium`
6. Reload PHP
   `sudo /etc/init.d/apache2 restart && service php7.0-fpm restart`
7. Check for libsodium with `php -m`

## Halite

1. Get composer
   `sudo apt-get install composer`
2. Navigate to your php project folder and install halite
   `composer require paragonie/halite`
3. Done

------

The above guide was contributed by [aolko](https://github.com/aolko) in [#48](https://github.com/paragonie/halite/issues/48).
