<template>
    <div>
      <button @click="generatePDF">Generar PDF</button>
    </div>
  </template>
  
  <script>
 import jsPDF from 'jspdf';
import Chart from 'chart.js/auto';

export default {
  methods: {
    generatePDF() {
      // Crear una instancia de jsPDF
      const doc = new jsPDF();

      // Agregar contenido al PDF
      doc.text('¡Hola, este es un PDF generado desde Vue.js!', 10, 10);

      // Obtener la imagen de la gráfica en formato base64
      const chartImageBase64 = this.$refs.chartImageBase64.value;

      // Insertar la imagen de la gráfica en el PDF
      doc.addImage(chartImageBase64, 'JPEG', 10, 30, 180, 150);

      // Guardar el PDF en el sistema de archivos del usuario
      doc.save('documento.pdf');
    },
    plotPieChart() {
      const ctx = this.$refs.chart.getContext('2d');
      const percentages = [
        parseFloat(this.getPercentage('severity').replace('%', '')),
        parseFloat(this.getPercentage('frequency').replace('%', '')),
        parseFloat(this.getPercentage('criticism').replace('%', ''))
      ];

      const chart = new Chart(ctx, {
        type: 'pie',
        data: {
          labels: ['Severity', 'Frequency', 'Criticism'],
          datasets: [{
            data: percentages,
            backgroundColor: ['rgba(255, 99, 132, 0.7)', 'rgba(54, 162, 235, 0.7)', 'rgba(255, 206, 86, 0.7)'],
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            title: { display: true, text: 'Porcentajes columnas de evaluación' },
            legend: { display: true, position: 'bottom' },
            tooltips: {
              callbacks: {
                label: function(context) {
                  let label = context.label || '';
                  if (label) label += ': ';
                  label += context.parsed + '%';
                  return label;
                }
              }
            }
          }
        }
      });

      // Obtener la imagen de la gráfica en formato base64
      this.$refs.chartImageBase64.value = chart.toBase64Image();
    }
  },
  mounted() {
    // Llamar a la función para generar la gráfica
    this.plotPieChart();
  }
}
  </script>
  