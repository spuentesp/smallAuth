package models

type Permission struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"uniqueIndex;not null"`
	Description string
	Roles       []Role `gorm:"many2many:role_permissions;"`
}
