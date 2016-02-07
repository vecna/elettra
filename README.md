
Greetings readers, this is Elettra first release.


# WHAT'S ELETTRA ?

Elettra is a software providing plausible deniablale cryptography. support a dynamic number of files and require a password for each file.

when you need to decrypt a file, the password is able to found in the encrypted archive the file related to it.

the security measure is in the protection of the number of files encrypted in the archive, because the algorith is think to give a plausible ammission that the data unencrypted is simple random data, and only one file is encrypted in it.

for more information about elettra and julia, http://www.phrack.org the issue #65 had an our article about elettra.

### REQUIREMENTS

aptitude install cmake libmhash-dev libmcrypt-dev zlib1g-dev

or, get the libraries at:

	http://sourceforge.net/projects/mcrypt
	http://sourceforge.net/projects/mhash
	http://www.zlib.net/
	http://www.cmake.org/HTML/Index.html

## HOW TO COMPILE

    user@linz:~/elettra/src$ mkdir build
    user@linz:~/elettra/src$ cd build/
    user@linz:~/elettra/src/build$ cmake ..
    -- Check for working C compiler: /usr/bin/gcc
    -- Check for working C compiler: /usr/bin/gcc -- works
    -- Check size of void*
    -- Check size of void* - done
    -- Configuring done
    -- Generating done
    -- Build files have been written to: /home/user/elettra/src/build
    user@linz:~/elettra/src/build$ make
    Scanning dependencies of target elettra
    [ 16%] Building C object CMakeFiles/elettra.dir/elettra.o
    [ 33%] Building C object CMakeFiles/elettra.dir/elettra_hidden.o
    [ 50%] Building C object CMakeFiles/elettra.dir/elettra_seek.o
    [ 66%] Building C object CMakeFiles/elettra.dir/elettra_utils.o
    [ 83%] Building C object CMakeFiles/elettra.dir/elettra_zlib.o
    [100%] Building C object CMakeFiles/elettra.dir/elettra_check.o
    Linking C executable elettra
    [100%] Built target elettra
    user@linz:~/elettra/src/build$ 

## HOW TO USE

Elettra has five command: encrypt, decrypt, checkpass, help and example.

is executed with: elettra command [args]

we want to encrypt file /tmp/ls-manpage and /tmp/ps-manpage. 
two file = two password we use "weirdness" and "foxnewsshower", 
the order link:
	ls-manpage (weirdness)
	ps-manpage (foxnewsshower)

    $ ./elettra encrypt /dev/shm/out 15% /tmp/ls-manpage::weirdness /tmp/ps-manpage::foxnewsshower

the size of our source file are:

    $ ls -l /tmp/ls-manpage /tmp/ps-manpage 
    -rw-r--r-- 1 user user  7132 Jan  8 05:57 /tmp/ls-manpage
    -rw-r--r-- 1 user user 36287 Jan  8 05:57 /tmp/ps-manpage

the command line specifies 15% of random paddinig. Required args for the 
"encrypt" command, are the output file, the source files and the passwords 
If passwords are not inserted via command line, they are prompted 
interactively.

before the encryption gzip compression is used, the output file is:

    $ ls -l /dev/shm/out
    -rw-r--r-- 1 user user 42615 Jan  8 06:13 /dev/shm/out

now we have an encrypted archive. the elettra decryption routine takes a 
password and, optionally, a destination directory:

    $ ./elettra decrypt /dev/shm/out weirdness /dev/shm/
    $ ls -l /dev/shm/
    -rw-r--r-- 1 user user  7132 Jan  8 06:32 ls-manpage
    -rw-r--r-- 1 user user 42615 Jan  8 06:13 out

if you want to check your passwords, use the command "checkpass":

    ./elettra checkpass actresss weirdness shoeless
    password(s) combinations work ok, with password block of 2304 bytes, use it.

if checkpass or encrypt command receive a bad password sequence, notice 
to the users.

### HACKING

Elettra actually randomize the creation time (ctime) of generated file.
If you want remove this feature, you need to recompile elettra
removing the #define at line 240 in elettra.c

### VERIFY

    MD5 (src/CMakeLists.txt) = d4272bbb174daa229b13330efa5d1928
    MD5 (src/elettra.c) = 6ac6b4303e67f7a275ad83caa539f0f3
    MD5 (src/elettra.h) = 96d0fc271b8ec8e480f507b8e9de72aa
    MD5 (src/elettra_check.c) = dd90b9e2e5f47363da1d72863b365de8
    MD5 (src/elettra_encrypt.c) = e4387e58aebea9c0ea63715c6403a71e
    MD5 (src/elettra_seek.c) = 955756518f04f0c01fa2cc0ecedc8b50
    MD5 (src/elettra_utils.c) = 0feea9500d9e9f8d9ac833e01b7c3668
    MD5 (src/elettra_zlib.c) = ef5e6c1d98e1031c2d94fbf591e1d104

and this README is signed with our public key, in order to certify those
hashes.

### fluff 

we focus our work showing the lack of technical bases on law used for regulare Internet. In our view, the pratical demonstration that the real-security, for information and for the people, could not be achieved violating the privacy, could improve real-security in a way where human rights are protected and not sacrificed.

