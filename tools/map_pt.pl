# map_pt.pl - final mapping: extracted_pt/*.pt -> song + difficulty slot.
# Evidence chain: pt instrument names -> song folders -> discstock.csv slots -> stage csv modes.
# Slot assignment: ascending id within consecutive run -> ascending slot (id blocks are per-song);
#   near-identical files (overlap>=0.985) clustered as revisions/shared charts.
use strict; use warnings;

my %songwav; my @songs;
opendir(my $dh, "extracted") or die;
for my $dir (readdir $dh) {
    next unless -d "extracted/$dir";
    next if $dir =~ /^(\.|c0\d|d0\d|e0\d|ee00|g01|i01|m\d\d|n0\d|s0\d)$/;
    opendir(my $sd, "extracted/$dir") or next;
    my @w = grep { /\.wav$/i } readdir $sd;
    closedir $sd;
    next unless @w;
    $songwav{$dir} = { map { lc($_) => 1 } @w };
    push @songs, $dir;
}
closedir $dh;

my @ds; my %songslots;
open(my $cf, "<", "extracted/d02/discstock.csv") or die;
<$cf>;
while (<$cf>) {
    chomp; s/\r$//; my @f = split /,/;
    my %sl;
    for my $i (0..9) {
        my $lv = $f[3+$i*2]; my $sp = $f[4+$i*2];
        $sl{$i} = [$lv, $sp] if defined $lv && $lv > 0;
    }
    my $nm = $f[1]; $nm =~ s/^\@//;
    $ds[$f[0]] = { name => $nm, listname => $f[2], slots => \%sl } if %sl;
}
close $cf;
for my $r (@ds) { next unless $r;
    for my $s (keys %{$r->{slots}}) { $songslots{$r->{name}}{$s} = 1; } }

my $SLOTMODE = { 0 => "LP", 1 => "PP", 2 => "TP", 3 => "SP" };
sub slotinfo {
    my ($name, $slot) = @_;
    for my $r (@ds) { next unless $r;
        if ($r->{name} eq $name && exists $r->{slots}{$slot}) {
            my ($lv, $sp) = @{$r->{slots}{$slot}};
            return ($lv, $sp, $r->{listname});
        } }
    return ("?", "?", $_[0]);
}

my %files;
open(my $pf, "<", "crack_work/tools/ptmap.tsv") or die;
while (<$pf>) {
    chomp; s/\r$//; my @f = split /\t/;
    my ($fn, $notes, $hash, $inscnt, @ins) = @f;
    (my $id = $fn) =~ s/\.pt$//;
    $files{$id} = { notes => $notes, hash => $hash, ins => \@ins };
}
close $pf;

my %sim;
open(my $sf, "<", "crack_work/tools/pairs.tsv") or die;
while (<$sf>) {
    chomp; s/\r$//; my ($a, $b, $r) = split /\t/;
    ($a, $b) = ($b, $a) if $a > $b;
    $sim{"$a|$b"} = $r;
}
close $sf;
sub overlap { my ($a, $b) = @_;
    ($a, $b) = ($b, $a) if $a > $b;
    return $sim{"$a|$b"} // 0;
}

my (%unsolved, %bysong);
for my $id (keys %files) {
    my @ins = @{$files{$id}{ins}};
    my ($best, $bestcov) = ("", 0);
    for my $s (@songs) {
        my $hit = 0;
        for my $w (@ins) { $hit++ if $songwav{$s}{lc $w} }
        my $cov = @ins ? $hit/@ins : 0;
        if ($cov > $bestcov) { $bestcov = $cov; $best = $s; }
    }
    if ($bestcov >= 0.5) {
        (my $norm = $best) =~ s/^\@//;
        $files{$id}{song} = $norm; $files{$id}{cov} = $bestcov;
        push @{$bysong{$norm}}, $id;
    } else {
        $unsolved{$id} = join(" ", @{$files{$id}{ins}}[0..($#{$files{$id}{ins}} < 2 ? $#{$files{$id}{ins}} : 2)]);
    }
}

my @out; my @warn;
for my $song (sort keys %bysong) {
    my @ids = sort { $a <=> $b } @{$bysong{$song}};
    my @slots = sort { $a <=> $b } keys %{$songslots{$song} // {}};
    # cluster near-identical files (union-find)
    my %parent; $parent{$_} = $_ for @ids;
    my $find; $find = sub { my $x = shift; $parent{$x} eq $x ? $x : ($parent{$x} = $find->($parent{$x})) };
    for my $i (0..$#ids) { for my $j ($i+1..$#ids) {
        if (overlap($ids[$i], $ids[$j]) >= 0.985) {
            my ($a, $b) = ($find->($ids[$i]), $find->($ids[$j]));
            $parent{$b} = $a if $a ne $b;
        } } }
    my %clus; push @{$clus{$find->($_)}}, $_ for @ids;
    my @clusters = sort { $clus{$a}[0] <=> $clus{$b}[0] } keys %clus;
    my $nf = @ids; my $nc = @clusters; my $ns = @slots;
    my %slotof; my %tagof;
    if (!@slots) {
        $slotof{$_} = "?" for @ids;
    } elsif ($nc == $ns) {
        # clean case: cluster i -> slot i; extra members = revisions
        for my $ci (0..$#clusters) {
            my @mem = @{$clus{$clusters[$ci]}};
            for my $m (0..$#mem) {
                $slotof{$mem[$m]} = $slots[$ci];
                $tagof{$mem[$m]} = $m ? "rev-of:" . $mem[0] : "";
            }
        }
    } elsif ($nf == $ns) {
        # files == slots: direct 1:1; near-identical files = shared chart at two slots
        for my $i (0..$#ids) {
            $slotof{$ids[$i]} = $slots[$i];
            my $root = $find->($ids[$i]);
            $tagof{$ids[$i]} = "same-chart-as:" . $clus{$root}[0] if $clus{$root}[0] ne $ids[$i];
        }
        push @warn, "$song: files==slots==$nf but ".($nf-$nc)." near-dup (shared charts?)";
    } else {
        # count mismatch: assign first min(n,ns) by id order, rest = ?extra with best attachment
        my $n = $nf < $ns ? $nf : $ns;
        for my $i (0..$n-1) { $slotof{$ids[$i]} = $slots[$i]; }
        for my $i ($n..$#ids) {
            my ($bo, $bid) = (0, "");
            for my $j (0..$n-1) { my $o = overlap($ids[$i], $ids[$j]); if ($o > $bo) { $bo = $o; $bid = $ids[$j]; } }
            $slotof{$ids[$i]} = "?extra";
            $tagof{$ids[$i]} = sprintf "best:%s(%.2f)", $bid, $bo;
        }
        push @warn, "$song: files=$nf clusters=$nc slots=$ns (@slots)";
    }
    for my $id (@ids) {
        my $slot = $slotof{$id};
        my ($lv, $sp, $title) = ($slot =~ /^\d+$/) ? slotinfo($song, $slot) : ("?","?",$song);
        my $mt = (stat("p02/$id"))[9]; my @t = localtime($mt);
        my $ds = sprintf("%04d-%02d-%02d", $t[5]+1900, $t[4]+1, $t[3]);
        push @out, [$id, $song, $title, $slot, $SLOTMODE->{$slot} // "?", $lv, $files{$id}{notes}, $ds, $tagof{$id} // ""];
    }
}

open(my $of, ">", "extracted_pt_mapping.csv") or die;
print $of "file,song,title,slot,mode,level,notes,mtime,tag\n";
for my $r (sort { $a->[0] <=> $b->[0] } @out) { print $of join(",", @$r) . "\n"; }
close $of;
printf STDERR "wrote extracted_pt_mapping.csv: %d rows, %d unsolved\n", scalar @out, scalar keys %unsolved;
print STDERR "WARN: $_\n" for @warn;
print STDERR "UNSOLVED: $_ ($unsolved{$_})\n" for sort keys %unsolved;
