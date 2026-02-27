from pyasn1.type import univ, namedtype

# 1. Define your schemas
class Entries(univ.SequenceOf):
    componentType = univ.Sequence(componentType=namedtype.NamedTypes(
        namedtype.NamedType('id', univ.Integer()),
        namedtype.NamedType('value', univ.OctetString())
    ))

class Record(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entries', Entries())
    )

# 2. Instantiate and populate
record = Record()

# Create an inner sequence (Entry)
entries = Entries().setComponentByPosition(0)
# entries[0].setComponentByName('id', 1)
# entries[0].setComponentByName('value', 'first-item')
entries[0]['id'] = 1
entries[0]['value'] = 'first-item'

# Set the field in the parent record
# record.setComponentByName('entries', entries)
record['entries'] = entries
