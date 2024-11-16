# test/recipes/99-test_tls_migration.t

use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_tls_migration");

plan tests => 1;

ok(run(test(["tls_migration_test", srctop_file("apps", "server.pem"), srctop_file("apps", "server.pem")])), "running tls_migration_test");
