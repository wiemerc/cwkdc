from dataclasses import fields
from typing import TypeVar, Generic, get_args, get_origin

from loguru import logger
from pyasn1.type import tag
from pyasn1.type.namedtype import NamedType, NamedTypes
from pyasn1.type.univ import Sequence, SequenceOf


# This class is just there so that we can annotate a field with `Asn1SequenceOf[...]`, which is not possible with the pyasn1
# class `SequenceOf`.
T = TypeVar("T")
class Asn1SequenceOf(Generic[T]):
    pass


class Asn1Sequence:
    # TODO: Use a metaclass to automatically call create_pyasn1_schema()
    @classmethod
    def create_pyasn1_schema(cls):
        logger.debug(f"Creating pyasn1 schema for class '{cls.__name__}'")
        components: list[NamedType] = []
        for idx, field in enumerate(fields(cls)):
            if field.name == "appl_tag_num":
                continue
            logger.debug(f"Processing field '{field.name}' of type {field.type}")
            component_tag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, idx)
            if get_origin(field.type) == Asn1SequenceOf:
                logger.debug("Field is a SEQUENCE OF")
                component = SequenceOf(componentType=(get_args(field.type)[0])())
                components.append(
                    NamedType(
                        name=field.name,
                        asn1Object=component.subtype(explicitTag=component_tag)
                    )
                )
            elif issubclass(field.type, Asn1Sequence):
                logger.debug("Field is another SEQUENCE")
                components.append(
                    NamedType(
                        name=field.name,
                        asn1Object=(field.type.pyasn1_schema)().subtype(explicitTag=component_tag)
                    )
                )
            else:
                # TODO: Check that type is actually a pyasn1 type
                kwargs = {"explicitTag": component_tag}
                if "constraint" in field.metadata:
                    kwargs["subtypeSpec"] = field.metadata["constraint"]
                components.append(
                    NamedType(
                        name=field.name,
                        asn1Object=(field.type)().subtype(**kwargs)
                    )
                )

        if hasattr(cls, "appl_tag_num"):
            cls.pyasn1_schema = type(
                "Asn1SequenceSchema",
                (Sequence,),
                {
                    "tagSet": Sequence.tagSet.tagExplicitly(tag.Tag(
                        tag.tagClassApplication,
                        tag.tagFormatConstructed,
                        cls.appl_tag_num,
                    )),
                    "componentType": NamedTypes(*components)
                }
            )
        else:
            cls.pyasn1_schema = type(
                "Asn1SequenceSchema",
                (Sequence,),
                {
                    "componentType": NamedTypes(*components)
                }
            )


    def __post_init__(self):
        logger.debug(f"Assigning values to pyasn1 object of class {type(self)}")
        self.pyasn1_obj = self.pyasn1_schema()
        for field in fields(self):
            if field.name == "appl_tag_num":
                continue
            logger.debug(f"Setting field '{field.name}'")
            if get_origin(field.type) == Asn1SequenceOf:
                component_type = get_args(field.type)[0]
                for idx, val in enumerate(getattr(self, field.name)):
                    self.pyasn1_obj[field.name][idx] = component_type(val)
            elif issubclass(field.type, Asn1Sequence):
                # Assigning another sequence to a field is a bit tricky. You can't just assign the schema object because that's
                # missing the explicit context tag (has just a plain SEQUENCE tag). The solution is to obtain the existing slot
                # from the parent sequence (which has the correct explicit context tag, set when the schema class was created),
                # and then copy each field from the child sequence into it in-place.
                slot = self.pyasn1_obj[field.name]
                child_pyasn1_obj = getattr(self, field.name).pyasn1_obj
                for child_field in fields(field.type):
                    if child_field.name == 'appl_tag_num':
                        continue
                    slot[child_field.name] = child_pyasn1_obj[child_field.name]
            else:
                self.pyasn1_obj[field.name] = getattr(self, field.name)
