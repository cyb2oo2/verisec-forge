from scripts.check_p1_review_bundle import near_clone, shingles


def test_identical_and_whitespace_clones():
    assert near_clone(shingles("int f(int x) { return x + 1; }"),
                      shingles("int  f ( int x ) {\nreturn x+1; }"))


def test_distinct_code_and_empty():
    assert not near_clone(shingles("int foo() { return 1; }"), shingles("while (ready) send(buffer, size);"))
    assert not near_clone(set(), set())


def test_long_containment():
    short = " ".join(f"v{i}" for i in range(30))
    assert near_clone(shingles(short), shingles(short + " " + " ".join(f"z{i}" for i in range(100))))
