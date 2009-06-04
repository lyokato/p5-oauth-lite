package OAuth::Lite::Problems;

use strict;
use warnings;

use base 'Exporter';
use List::MoreUtils qw(any);

our %EXPORT_TAGS = ( all => [qw/
    VERSION_REJECTED
    PARAMETER_ABSENT
    PARAMETER_REJECTED
    TIMESTAMP_REFUSED
    NONCE_USED
    SIGNATURE_METHOD_REJECTED
    SIGNATURE_INVALID
    CONSUMER_KEY_UNKNOWN
    CONSUMER_KEY_REJECTED
    TOKEN_USED
    TOKEN_EXPIRED
    TOKEN_REVOKED
    TOKEN_REJECTED
    ADDITIONAL_AUTHORIZATION_REQUIRED
    PERMISSION_UNKNOWN
    USER_REFUSED
/] );

our @EXPORT_OK = map { @$_ } values %EXPORT_TAGS;

use constant VERSION_REJECTED                  => 'version_rejected';
use constant PARAMETER_ABSENT                  => 'parameter_absent';
use constant PARAMETER_REJECTED                => 'parameter_rejected';
use constant TIMESTAMP_REFUSED                 => 'timestamp_refused';
use constant NONCE_USED                        => 'nonce_used';
use constant SIGNATURE_METHOD_REJECTED         => 'signature_method_rejected';
use constant SIGNATURE_INVALID                 => 'signature_invalid';
use constant CONSUMER_KEY_UNKNOWN              => 'consumer_key_unknown';
use constant CONSUMER_KEY_REJECTED             => 'consumer_key_rejected';
use constant TOKEN_USED                        => 'token_used';
use constant TOKEN_EXPIRED                     => 'token_expired';
use constant TOKEN_REVOKED                     => 'token_revoked';
use constant TOKEN_REJECTED                    => 'token_rejected';
use constant ADDITIONAL_AUTHORIZATION_REQUIRED => 'additional_authorization_required';
use constant PERMISSION_UNKNOWN                => 'permission_unknown';
use constant USER_REFUSED                      => 'user_refused';

sub match {
    my $class = shift;
    my $error = shift;
    return (any { $error eq $class->$_() } @EXPORT_OK) ? 1 : 0;
}


1;

=head1 NAME

OAuth::Lite::Problems - constants for OAuth Problem Reporting Extension

=head1 SYNOPSIS

    use OAuth::Problems qw(:all);

    $server->error( TOKEN_REJECTED );

=head1 DESCRIPTION

This provides constants which used in OAuth Problem Reporting spec.

=head1 METHODS

=head2 match($error)

    my $error = 'token_rejected';
    if (OAuth::Lite::Problems->match($error)) {
        say "This error is OAuth Problem";
        $server->error(sprintf "oauth_problem=%s", $error);
    }


=head1 SEE ALSO

http://oauth.pbwiki.com/ProblemReporting

=head1 AUTHOR

Lyo Kato, C<lyo.kato _at_ gmail.com>

=head1 COPYRIGHT AND LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

