use Test::More tests => 8;

use OAuth::Lite::SignatureMethod::HMAC_SHA256;

is(OAuth::Lite::SignatureMethod::HMAC_SHA256->method_name, 'HMAC-SHA256');
is(OAuth::Lite::SignatureMethod::HMAC_SHA256->build_body_hash(qq{Hello World!}), q{f4OxZX/x/FO5LcGBSKHWXfwtSx+j1ncoSt3SABJtkGk=});

my $base = "hogehogehoge";

my $signer = OAuth::Lite::SignatureMethod::HMAC_SHA256->new(
	consumer_secret => 'foo',
	token_secret    => 'bar',
);

my $signature = $signer->sign($base);
is($signature, q{zCPAAJkxoV1y0Qk68zOmNk6MIh0gjjbnApjLi7HXxu8=});

my $verifier = OAuth::Lite::SignatureMethod::HMAC_SHA256->new(
	consumer_secret => 'foo',
	token_secret    => 'bar',
);

my $invalid_verifier = OAuth::Lite::SignatureMethod::HMAC_SHA256->new(
	consumer_secret => 'foo',
	token_secret    => 'invalid',
);

ok($verifier->verify($base, $signature));
ok(!$invalid_verifier->verify($base, $signature));

my $signer2 = OAuth::Lite::SignatureMethod::HMAC_SHA256->new(
	consumer_secret => 'foo',
);

my $signature2 = $signer2->sign($base);
is($signature2, q{hkZq+sUGA9d/YoW1+Uv/UmtXoUSYJ9SbCG4F09SfvwY=});

my $verifier2 = OAuth::Lite::SignatureMethod::HMAC_SHA256->new(
	consumer_secret => 'foo',
);

ok($verifier2->verify($base, $signature2));
ok(!$invalid_verifier->verify($base, $signature2));

