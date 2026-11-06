
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

from app.intelligence.repository import IntelligenceRepository

from test_threat_intelligence_persistence import build_assessment


def test_history_reads_remain_consistent_during_concurrent_writes(
    isolated_database,
):
    repository = IntelligenceRepository()

    writer_count = 4
    assessments_per_writer = 10
    reader_count = 4
    total_writes = writer_count * assessments_per_writer

    total_workers = writer_count + reader_count
    start_barrier = Barrier(total_workers)

    base_time = build_assessment().assessed_at

    assessments = [
        build_assessment(score=index).model_copy(
            update={
                "assessed_at": base_time + timedelta(seconds=index)
            }
        )
        for index in range(total_writes)
    ]

    def writer(start_index):
        start_barrier.wait(timeout=15)

        saved_ids = []

        for offset in range(assessments_per_writer):
            index = start_index + offset

            assessment_id = repository.save_assessment(
                assessments[index]
            )

            saved_ids.append(assessment_id)

        return saved_ids

    def reader():
        start_barrier.wait(timeout=15)

        observations = []

        for _ in range(30):
            history = repository.get_assessments_by_ip(
                "8.8.8.8",
                limit=100,
            )

            assert len(history) <= total_writes

            for item in history:
                assert item["id"] is not None
                assert item["ip_address"] == "8.8.8.8"
                assert item["threat_score"] is not None

            timestamps = [
                (item["assessed_at"], item["id"])
                for item in history
            ]

            assert timestamps == sorted(
                timestamps,
                reverse=True,
            )

            # Every visible assessment must have all its provider
            # results available after its transaction has committed.
            for item in history:
                stored = repository.get_assessment(item["id"])

                assert stored is not None
                assert len(stored["provider_results"]) == 2

                providers = {
                    result["provider"]
                    for result in stored["provider_results"]
                }

                assert providers == {
                    "abuseipdb",
                    "secondary_provider",
                }

            observations.append(len(history))

        return observations

    with ThreadPoolExecutor(max_workers=total_workers) as executor:
        futures = []

        for writer_index in range(writer_count):
            start_index = (
                writer_index * assessments_per_writer
            )

            futures.append(
                executor.submit(writer, start_index)
            )

        reader_futures = [
            executor.submit(reader)
            for _ in range(reader_count)
        ]

        writer_results = [
            future.result(timeout=60)
            for future in futures
        ]

        reader_results = [
            future.result(timeout=60)
            for future in reader_futures
        ]

    saved_ids = [
        assessment_id
        for result in writer_results
        for assessment_id in result
    ]

    assert len(saved_ids) == total_writes
    assert len(set(saved_ids)) == total_writes

    assert len(reader_results) == reader_count

    for observations in reader_results:
        assert len(observations) == 30
        assert all(
            0 <= count <= total_writes
            for count in observations
        )

    final_history = repository.get_assessments_by_ip(
        "8.8.8.8",
        limit=100,
    )

    assert len(final_history) == total_writes

    assert {
        item["id"]
        for item in final_history
    } == set(saved_ids)


def test_assessment_reads_never_expose_partial_provider_results(
    isolated_database,
):
    repository = IntelligenceRepository()

    assessment = build_assessment()

    assessment_id = repository.save_assessment(assessment)

    stored = repository.get_assessment(assessment_id)

    assert stored is not None
    assert stored["ip_address"] == assessment.ip_address

    assert len(stored["provider_results"]) == len(
        assessment.provider_results
    )

    assert {
        result["provider"]
        for result in stored["provider_results"]
    } == {
        "abuseipdb",
        "secondary_provider",
    }
