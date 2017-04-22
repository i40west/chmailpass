# chmailpass
A chpass command to change passwords stored in an SQLite database.

I don't allow login passwords on servers because it's, you know, the 21st Century.
SSH public-key only. So my mail servers (and Apache) are configured to use passwords
stored in an SQLite database. Users need a way to change their passwords. This is it.

I run it on FreeBSD and can't attest to it working anwhere else. It does compile and
work on macOS but I've never actually used it there. I've used it in production on
FreeBSD for more than a decade.

It's in an Xcode project because I work in Xcode. All you need is chmailpass.c and
the Makefile.

It needs to be installed setuid root, on the assumption that the SQLite database is
not readable by other users, which it obviously shouldn't be. The Makefile will do
that for you.

You'll need to set the location of the SQLite database file at the top of the source.

# SQLite schema

    CREATE TABLE passwd (
      id text primary key,
      crypt text not null default '',
      clear text not null default '',
      name text not null default '',
      uid integer not null default 65534,
      gid integer not null default 65534,
      login text not null default '',
      email text not null default '',
      home text not null default '',
      maildir text not null default ''
    );

This program does not create or populate the table. This is left as an exercise for
the reader. My mail servers are configured to use the table to determine the user's
mail directory; this too is left as an exercise for the reader. If you're in a
position to use this I assume you know how to do that.
