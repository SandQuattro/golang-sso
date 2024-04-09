package utils

func Ternary(cond bool, a any, b any) any {
	if cond {
		return a
	}
	return b
}
