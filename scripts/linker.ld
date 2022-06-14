ENTRY( Entry )

SECTIONS
{
	.text ALIGN(1) : SUBALIGN(1)
	{
		*(.text.Entry)
		*(.text.*)
	}
}
