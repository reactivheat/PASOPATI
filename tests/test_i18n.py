import string

import pasopati
from pasopati.i18n import MESSAGES, Language, tr


def test_catalogs_have_matching_keys_and_placeholders() -> None:
    en, id_ = MESSAGES[Language.EN], MESSAGES[Language.ID]
    assert en.keys() == id_.keys()
    formatter = string.Formatter()
    for key in en:
        fields_en = {field for _, field, _, _ in formatter.parse(en[key]) if field}
        fields_id = {field for _, field, _, _ in formatter.parse(id_[key]) if field}
        assert fields_en == fields_id, key
        assert en[key] and id_[key]


def test_language_selection_and_metadata() -> None:
    assert tr(Language.EN, "quick_start") == "Quick start"
    assert tr(Language.ID, "quick_start") == "Panduan singkat"
    assert pasopati.get_version()
