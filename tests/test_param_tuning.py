from Lattice_IBPRE.src.param_tuning import ParameterTuner
from Lattice_IBPRE.src.main import run_parameter_tuning_suite


NS = (8, 12, 16)
QS = (8191, 16381, 32771)
SIGMAS = (0.3, 0.5)


def _timing_entry(rekeygen, encrypt, reencrypt):
    return {
        "setup": 0.001,
        "extract": 0.002,
        "rekeygen": rekeygen,
        "encrypt": encrypt,
        "reencrypt": reencrypt,
        "decrypt": 0.003,
        "redecrypt": 0.004,
    }


DUMMY_PARAMETER_GRID = tuple(
    {"n": n, "q": q, "sigma": sigma}
    for n in NS
    for q in QS
    for sigma in SIGMAS
)


DUMMY_TIMING_DATA = {}
for idx_n, n in enumerate(NS, 1):
    for idx_q, q in enumerate(QS, 1):
        for sigma in SIGMAS:
            base = idx_n * 100 + idx_q * 10 + (5 if sigma == 0.5 else 0)
            DUMMY_TIMING_DATA[(n, q, sigma)] = _timing_entry(
                rekeygen=10.0 + base,
                encrypt=1.0 + base / 100,
                reencrypt=2.0 + base / 50,
            )


DUMMY_SIZE_DATA = {
    "pp_bytes": 1.0,
    "sk_bytes": 2.0,
    "rk_bytes": 3.0,
    "ciphertext_bytes": 4.0,
    "re_ciphertext_bytes": 5.0,
}


def _build_tuner():
    return ParameterTuner(
        method="thesis",
        parameter_grid=DUMMY_PARAMETER_GRID,
        timing_data=DUMMY_TIMING_DATA,
        size_data=DUMMY_SIZE_DATA,
        verbose=False,
    )


def test_parameter_tuner_returns_all_parameter_results():
    tuner = _build_tuner()
    results = tuner.results()
    assert len(results) == len(DUMMY_PARAMETER_GRID)
    assert any(result.n == 8 and result.q == 8191 for result in results)


def test_run_parameter_tuning_suite_exposes_entries_sorted_by_dimension():
    results = run_parameter_tuning_suite(
        method="thesis",
        parameter_grid=DUMMY_PARAMETER_GRID,
        timing_data=DUMMY_TIMING_DATA,
        size_data=DUMMY_SIZE_DATA,
        verbose=False,
    )
    entries = results['entries']
    assert len(entries) == len(DUMMY_PARAMETER_GRID)
    assert entries[0].n == 8 and entries[0].q == 8191
    assert entries[-1].n == 16 and entries[-1].q == 32771
