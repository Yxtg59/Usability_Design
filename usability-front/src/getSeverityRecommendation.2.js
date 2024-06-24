export const getSeverityRecommendation = (percentage) => {
if (percentage < 1) {
return "Severidad Baja: No es un problema de usabilidad.";
} else if (percentage <= 10) {
return "Severidad Baja-Media: Problema 'Cosmético'; no necesita ser resuelto a menos que se disponga de tiempo extra en el proyecto.";
} else if (percentage <= 50) {
return "Severidad Media: Problema de usabilidad menor: arreglarlo tiene baja prioridad.";
} else if (percentage <= 90) {
return "Severidad Alta: Problema de usabilidad mayor: es importante arreglarlo.";
}
};
