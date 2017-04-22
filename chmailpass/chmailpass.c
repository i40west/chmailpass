/*
 Copyright (c) 2012 Jeremy Nixon. All rights reserved.

 Developed by: Jeremy Nixon

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 with the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimers.

 Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimers in the documentation
 and/or other materials provided with the distribution.

 Neither the names of the developer nor the names of its contributors may be
 used to endorse or promote products derived from this Software without
 specific prior written permission.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH
 THE SOFTWARE.
 */

/* Change or set email password in the sqlite database. */

/*
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
 */

#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#include <sqlite3.h>

static void open_db(void);
static void close_db(void);
static sqlite3_stmt *sql_stmt_int(char *sql, int arg);
static int id_for_login(char **id);
static int current_password_for_user(char *u, char **password);
static int set_password_for_user(char *user, char *newpass);
static bool access_to_user(char *user);
static char *make_salt(void);
static int i64c(int i);

static const char *dbfile = "/usr/local/etc/auth/passwd.db";
static sqlite3 *db;
static bool opened = false;

static uid_t real_uid;
static uid_t effective_uid;

int main(int argc, char *argv[])
{
    real_uid = getuid();
    effective_uid = geteuid();

    if (effective_uid != 0) {
        printf("Must be run as root or be setuid.\n");
        exit(1);
    }

    if (argc > 2) {
        printf("Usage: %s [username]\n",argv[0]);
        exit(1);
    }

    char *mailuser;    // The mail login we're changing.
    char *currpassdb;  // The current password from the database.
    int f;
    open_db();

    if (argc == 2) {
        if (strlen(argv[1]) > 255) {
            printf("Argument too long.\n");
            close_db();
            exit(1);
        }
        bool a = access_to_user(argv[1]);
        if (!a) {
            printf("Access denied.\n");
            close_db();
            exit(1);
        }
        mailuser = malloc(strlen(argv[1]) + 1);
        strncpy(mailuser,argv[1],strlen(argv[1]));
    } else {
        f = id_for_login(&mailuser);
        if (f == 1) {
            printf("No mail login found.\n");
            close_db();
            free(mailuser);
            exit(1);
        } else if (f == -1) {
            printf("You have more than one mail login.\n");
            printf("Invoke this program with login on command line.\n");
            close_db();
            free(mailuser);
            exit(0);
        }
    }
    // At this point we have exactly one mail login.
    // mailuser is valid and contains the string.

    // Get the current password from the database.
    f = current_password_for_user(mailuser,&currpassdb);

    // If the current password is empty, we are setting the password.
    // If running as root, we are setting the password.
    if (real_uid == 0 || strlen(currpassdb) == 0) {
        printf("Setting password for mail login %s...\n",mailuser);

    } else {
        printf("Changing password for mail login %s...\n",mailuser);

        // Get the current password from the user for verification.
        char *currpass = getpass("\nCurrent password: ");

        // Verify against the existing password.
        char salt[3];
        strncpy(salt,currpassdb,2);
        salt[2] = '\0';

        char *result = crypt(currpass,salt);
        if (strcmp(result,currpassdb) != 0) {
            printf("Password incorrect.\n");
            close_db();
            free(mailuser);
            free(currpassdb);
            exit(1);
        }
    }
    // Verification succeeded.

    free(currpassdb);

    // Get a new password from the user.
    char *np = getpass("New password: ");
    if (strlen(np) == 0) {
        printf("\npassword not changed.\n");
        close_db();
        free(mailuser);
        exit(1);
    }
    // getpass uses a static buffer, so we need to make a copy.
    char *newpass = malloc(strlen(np)+1);
    strncpy(newpass,np,strlen(np)+1);

    np = getpass("Verify password: ");
    if (strcmp(newpass,np) != 0) {
        printf("\npasswords don't match, no changes made.\n");
        close_db();
        free(mailuser);
        free(newpass);
        exit(1);
    }

    // Store the new password in the database.
    if (set_password_for_user(mailuser,newpass) != 0) {
        close_db();
        free(mailuser);
        free(newpass);
        exit(1);
    }

    free(mailuser);
    free(newpass);
    close_db();
    exit(0);
}

static void open_db(void)
{
    if (opened == true) return;
    if (sqlite3_initialize() != SQLITE_OK) {
        fprintf(stderr, "Failed to initialize sqlite library.\n");
        exit(1);
    }
    if (sqlite3_open_v2(dbfile,&db,
                        SQLITE_OPEN_READWRITE,NULL) != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }
    (void)sqlite3_busy_timeout(db,1200);
    opened = true;
}

static void close_db(void)
{
    int rc;
    if (opened == false) return;

    rc = sqlite3_close(db);
    if (rc == SQLITE_BUSY) {
        fprintf(stderr, "warning: unfinalized statements while trying to "
                "close database, possible bug.\n");
        sqlite3_stmt *st;
        while ((st = sqlite3_next_stmt(db,0)) != 0) {
            sqlite3_finalize(st);
        }
        rc = sqlite3_close(db);
    }
    if (rc != SQLITE_OK) {
        fprintf(stderr, "error closing database, not good: %s\n",
                sqlite3_errmsg(db));
        exit(1);
    }
    sqlite3_shutdown();
    opened = false;
}

/*
 Convenience function to generate an sqlite3 stmt with a bound int.
 */
static sqlite3_stmt *sql_stmt_int(char *sql, int arg)
{
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,sql,(int)strlen(sql),&stmt,NULL) != SQLITE_OK) {
        fprintf(stderr, "Error preparing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_db();
        exit(1);
    }
    if (sqlite3_bind_int(stmt,1,arg) != SQLITE_OK) {
        fprintf(stderr, "Can't bind value: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_db();
        exit(1);
    }
    return stmt;
}

/*
 Find the mail id for the current user.
 If there is more than one, error.
 If success, return 0 and put pointer to the id in *id.
 Returned string is obtained from malloc and should be freed.
 */
static int id_for_login(char **id)
{
    char *sql = "select id from passwd where uid = ?";
    sqlite3_stmt *stmt = sql_stmt_int(sql,real_uid);

    char *l;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *r = (char *)sqlite3_column_text(stmt,0);
        l = malloc(strlen(r)+1);
        strncpy(l,r,strlen(r));
        *id = l;
    } else if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 1;
    } else {
        fprintf(stderr, "Error fetching row: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_db();
        exit(1);
    }

    // more than one mail id.
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

static int current_password_for_user(char *user, char **password)
{
    sqlite3_stmt *stmt;
    char *sql = sqlite3_mprintf("select crypt from passwd where id = %Q",user);

    if (sqlite3_prepare_v2(db,sql,(int)strlen(sql),&stmt,NULL) != SQLITE_OK) {
        fprintf(stderr, "Error preparing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_db();
        exit(1);
    }

    char *pw;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *r = (char *)sqlite3_column_text(stmt,0);
        pw = malloc(strlen(r)+1);
        strncpy(pw,r,strlen(r)+1);
        *password = pw;
        sqlite3_finalize(stmt);
        sqlite3_free(sql);
        return 0;
    } else if (rc == SQLITE_DONE) {
        fprintf(stderr, "User suddenly not found, error.\n");
        sqlite3_finalize(stmt);
        sqlite3_free(sql);
        exit(1);
    } else {
        fprintf(stderr, "Error fetching row: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_free(sql);
        close_db();
        exit(1);
    }
}

static int set_password_for_user(char *user, char *newpass)
{
    char *salt = make_salt();
    char *newcrypt = crypt(newpass,salt);

    char *sql = sqlite3_mprintf("update passwd set crypt = %Q where id = %Q",
                                newcrypt,user);

    int rc = sqlite3_exec(db,sql,NULL,NULL,NULL);
    sqlite3_free(sql);
    if (rc != SQLITE_OK) {
        fprintf(stderr,"\nError setting new password: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    return 0;
}

/* Check for a row with the login's uid and the username. */
static bool access_to_user(char *user)
{
    if (0 == real_uid) {
        return true;
    }

    char *sql = sqlite3_mprintf("select id from passwd where uid = ? and id = %Q",user);
    sqlite3_stmt *stmt = sql_stmt_int(sql,real_uid);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // We found a row, so the user has access.
        sqlite3_finalize(stmt);
        return true;
    } else if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return false;
    } else {
        fprintf(stderr, "sqlite error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        close_db();
        exit(1);
    }
}

static char *make_salt(void)
{
    static unsigned long x;
    static char salt[3];

    x += time(NULL) + getpid() + clock();
    salt[0] = i64c(((x >> 18) ^ (x >> 6)) & 077);
    salt[1] = i64c(((x >> 12) ^ x) & 077);
    salt[2] = '\0';
    return salt;
}

// cargo-culted from somewhere on the net.
static int i64c(int i)
{
    i &= 0x3f;
    if (i == 0) return '.';
    if (i == 1) return '/';
    if (i < 12) return ('0' - 2 + i);
    if (i < 38) return ('A' - 12 + i);
    return ('a' - 38 + i);
}
