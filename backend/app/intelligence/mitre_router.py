from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import get_current_actor

from app.intelligence.mitre import MITREAttackMapper


router = APIRouter(
    prefix="/api/v1/mitre",
    tags=["MITRE ATT&CK"],
    dependencies=[Depends(get_current_actor)],
)


@router.get("/techniques")
def get_techniques():
    techniques = MITREAttackMapper.get_all_techniques()

    return {
        "count": len(techniques),
        "techniques": [
            technique.to_dict()
            for technique in techniques
        ],
    }


@router.get("/search")
def search_techniques(
    q: str = Query(min_length=1, max_length=100),
):
    techniques = MITREAttackMapper.search_techniques(q)

    return {
        "query": q,
        "count": len(techniques),
        "techniques": [
            technique.to_dict()
            for technique in techniques
        ],
    }


@router.get("/mappings")
def get_rule_mappings():
    mappings = MITREAttackMapper.get_all_rule_mappings()

    return {
        "count": len(mappings),
        "mappings": mappings,
    }


@router.get("/rules/{rule_id}")
def get_rule_mapping(rule_id: str):
    mapping = MITREAttackMapper.get_rule_mapping(rule_id)

    if not mapping["mapped"]:
        raise HTTPException(
            status_code=404,
            detail=f"No MITRE ATT&CK mapping found for rule {rule_id}",
        )

    return mapping


@router.get("/techniques/{technique_id}")
def get_technique(technique_id: str):
    technique = MITREAttackMapper.get_technique(technique_id)

    if technique is None:
        raise HTTPException(
            status_code=404,
            detail=f"MITRE ATT&CK technique {technique_id} not found",
        )

    return technique.to_dict()
