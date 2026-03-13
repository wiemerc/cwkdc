from dataclasses import dataclass, fields
from typing import TypeVar, Generic, get_args, get_origin

from loguru import logger
from pyasn1.type import tag
from pyasn1.type.namedtype import NamedType, NamedTypes, OptionalNamedType
from pyasn1.type.univ import Sequence, SequenceOf


# This class is just there so that we can annotate a field with `Asn1SequenceOf[...]`, which is not possible with the pyasn1
# class `SequenceOf`.
T = TypeVar("T")
class Asn1SequenceOf(Generic[T]):
    pass


class Asn1Sequence:
    def __init_subclass__(cls, **kwargs): 
        logger.debug(f"Creating pyasn1 schema for class '{cls.__name__}'")
        dataclass(cls)
        components: list[NamedType | OptionalNamedType] = []
        for field in fields(cls):
            if field.name == "appl_tag_num":
                continue
            logger.debug(f"Processing field '{field.name}' of type {field.type}")
            component_tag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, field.metadata["tag"])
            component_is_optional = get_args(field.type) and type(None) in get_args(field.type)
            field_type = get_args(field.type)[0] if component_is_optional else field.type
            component_type = OptionalNamedType if component_is_optional else NamedType
            if get_origin(field_type) is Asn1SequenceOf:
                logger.debug("Field is a SEQUENCE OF")
                component = SequenceOf(componentType=(get_args(field_type)[0])())
                components.append(
                    component_type(
                        name=field.name,
                        asn1Object=component.subtype(explicitTag=component_tag)
                    )
                )
            elif issubclass(field_type, Asn1Sequence):
                logger.debug("Field is another SEQUENCE")
                components.append(
                    component_type(
                        name=field.name,
                        asn1Object=(field_type.pyasn1_schema)().subtype(explicitTag=component_tag)
                    )
                )
            else:
                # TODO: Check that type is actually a pyasn1 type (or derived from one)
                kwargs = {"explicitTag": component_tag}
                if "constraint" in field.metadata:
                    kwargs["subtypeSpec"] = field.metadata["constraint"]
                components.append(
                    component_type(
                        name=field.name,
                        asn1Object=(field_type)().subtype(**kwargs)
                    )
                )

        if hasattr(cls, "appl_tag_num"):
            cls.pyasn1_schema = type(
                f"{cls.__name__}Schema",
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
                f"{cls.__name__}Schema",
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
            if getattr(self, field.name) is None:
                continue
            logger.debug(f"Setting field '{field.name}'")
            component_is_optional = get_args(field.type) and type(None) in get_args(field.type)
            field_type = get_args(field.type)[0] if component_is_optional else field.type
            if get_origin(field_type) is Asn1SequenceOf:
                component_type = get_args(field.type)[0]
                for idx, val in enumerate(getattr(self, field.name)):
                    self.pyasn1_obj[field.name][idx] = component_type(val)
            elif issubclass(field_type, Asn1Sequence):
                # Assigning another sequence to a field is a bit tricky. You can't just assign the schema object because that's
                # missing the explicit context tag (has just a plain SEQUENCE tag). The solution is to obtain the existing slot
                # from the parent sequence (which has the correct explicit context tag, set when the schema class was created),
                # and then copy each field from the child sequence into it in-place.
                slot = self.pyasn1_obj[field.name]
                child_pyasn1_obj = getattr(self, field.name).pyasn1_obj
                for child_field in fields(field_type):
                    if child_field.name == 'appl_tag_num':
                        continue
                    slot[child_field.name] = child_pyasn1_obj[child_field.name]
            else:
                self.pyasn1_obj[field.name] = getattr(self, field.name)
