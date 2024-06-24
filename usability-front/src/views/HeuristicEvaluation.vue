<!-- eslint-disable no-unused-vars -->
<script setup>
import { ref, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import axios from 'axios';
import Chart from 'chart.js/auto';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';
import ChartDataLabels from 'chartjs-plugin-datalabels';




// fragmento de código que inicializa  variables para almacenar datos relacionados con 
// problems y observations, y utiliza Vue Router para acceder a la ruta actual y al enrutador.
const route = useRoute();
const router = useRouter();
const problems = ref([]);
const observations = ref([]);

//fragmento de código de una variable referencia reactiva que almacena una lista de opciones,
 //donde cada opción es un objeto con dos propiedades text y value
const options = ref([
  { text: '0', value: 0 },
  { text: '1', value: 1 },
  { text: '2', value: 2 },
  { text: '3', value: 3 },
  { text: '4', value: 4 },
]);

// fragmento de código que permite obtención de datos y la representación gráfica de los mismos.
onMounted(async () => {
  console.log("mounted");
  await Promise.all([getallproblems(), getObservations()]);
  plotPieChart();
});

//fragmento de código  que se encarga de guardar la evaluación de un propietario en el servidor y luego redirigir al usuario a la página de resultados de la evaluación
const saveEvaluation = async () => {
  const ownerid = route.params.ownerId;
  console.log("evaluacion guardada ", problems.value);
  try {
    const response = await axios.post(`http://127.0.0.1:5000/evaluations/${ownerid}`, problems.value);
    console.log(response);
    router.push(`/o/${ownerid}/resultadoevaluacion`);
  } catch (error) {
    console.error(error);
  }
};

//fragmento de código que se encarga de obtener los problemas identificados para un propietario específico desde el servidor.
const getallproblems = async () => {
  try {
    const response = await axios.get(`http://127.0.0.1:5000/identifyproblems/${route.params.ownerId}`);
    problems.value = response.data;
    console.log("Problems:", problems.value);
  } catch (error) {
    console.error("Error fetching problems:", error);
  }
};

//fragmento de código que se encarga de obtener las observaciones asociadas a un propietario específico desde el servidor.
const getObservations = async () => {
  try {
    const response = await axios.get(`http://127.0.0.1:5000/getobservations/${route.params.ownerId}`);
    observations.value = response.data;
    console.log("Observations:", observations.value);
  } catch (error) {
    console.error("Error fetching observations:", error);
  }
};

// fragmento de código para calcular la suma de cada columna severity,frequency y criticism
const getColumnSum = (columnName) => {
  return problems.value.reduce((sum, item) => {
    return sum + parseFloat(item[columnName] || 0);
  }, 0);
};

//fragmento de código que permite mantener un seguimiento dinámico del total de cada columna a medida que los datos cambian
const columnSums = {
  severity: ref(0),
  frequency: ref(0),
  criticism: ref(0),
};


//fragmento de código que permite actualizar dinámicamente el total de la columna
const updateColumnSum = (columnName) => {
  columnSums[columnName].value = getColumnSum(columnName);
};

// cambios en los valores de las columnas 
watch(() => problems.value.map(item => item.severity), () => updateColumnSum('severity'));
watch(() => problems.value.map(item => item.frequency), () => updateColumnSum('frequency'));
watch(() => problems.value.map(item => item.criticism), () => updateColumnSum('criticism'));


// fragmento de código para calcular el porcentaje del resultado de la suma  de la columna severyty,frequency y critiscism
const getPercentage = (column) => {
  let maxValue;
  if (column === 'criticism') {
    maxValue = 584;
  } else {
    maxValue = 292; 
  }
  
  const columnSum = getColumnSum(column);
  const percentage = (columnSum / maxValue) * 100;
  return `${percentage.toFixed(2)}%`;
};

//fragmento de coódigo para calcular la suma total de los porcentajes calculados 

const getTotalPercentage = () => {
  const severityPercentage = parseFloat(getPercentage('severity').replace('%', '')); 
  const frequencyPercentage = parseFloat(getPercentage('frequency').replace('%', '')); 
  const criticismPercentage = parseFloat(getPercentage('criticism').replace('%', '')); 
  
  // fragmento de código para calcular el promedio de ,los porcentajes de las columnas
  const promedioPercentage = ((severityPercentage + frequencyPercentage + criticismPercentage) / 3).toFixed(2);
  
  return `${promedioPercentage}%`;
};

 //fragmento de código que permite dar el rango de problema de la evaluación que varia según el porcentaje total
const getRecommendation = () => {
const promedioPercentage = parseFloat(getTotalPercentage().replace('%', ''));

  //fragmento de código que permite dar el rango de problema de la evaluación que varia según el porcentaje total
  if (promedioPercentage < 1) {
    return 'No es un problema de usabilidad.';
  } else if (promedioPercentage <= 10) {
    return 'Problema "Cosmético"; no necesita ser resuelto a menos que se disponga de tiempo extra en el proyecto.';
  } else if (promedioPercentage <= 50) {
    return 'Problema de usabilidad menor: arreglarlo tiene baja prioridad.';
  } else if (promedioPercentage >= 90) {
    return 'Problema de usabilidad mayor: es importante arreglarlo.';
  } else {
    return 'Problema de usabilidad catastrófico: es imperativo arreglarlo antes de que el producto sea liberado.';
  }
};


// Métodos específicos para las gráficas de porcentaje
// fragmento de código  variable para alamcenar la instancia del gráfico
let pieChart = null; 

const plotPieChart = (severityPercentage, frequencyPercentage, criticismPercentage) => {
  const ctx = document.getElementById('pie-chart').getContext('2d');

  // fragmento de código que elimina la instancia de gráfico existente 
  if (pieChart) {
    pieChart.destroy();
  }

  // fragmento de código que crea una nueva instancia de gráfico
  pieChart = new Chart(ctx, {
    type: 'pie',
    data: {
      labels: ['Severity', 'Frequency', 'Criticism'],
      datasets: [{
        data: [severityPercentage, frequencyPercentage, criticismPercentage],
        backgroundColor: [
          'rgba(255, 99, 132, 0.7)',
          'rgba(54, 162, 235, 0.7)',
          'rgba(255, 206, 86, 0.7)',
        ],
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        title: {
          display: true,
          text: 'Porcentajes columnas de evaluación'
        },
        legend: {
          display: true,
          position: 'bottom'
        },
        // Agregar etiquetas
        tooltips: {
          callbacks: {
            label: function(context) {
              let label = context.label || '';

              if (label) {
                label += ': ';
              }
              label += context.parsed + '%';
              return label;
            }
          }
        },
        datalabels: {
          color: '#fff',
          anchor: 'end',
          align: 'start',
          formatter: (value, context) => {
            return value + '%';
          }
        }
      }
    },
    //fragmento de código permite mostrar etiquetas de datos los gráficos como los porcentajes
    plugins: [ChartDataLabels]
  });
};

const updatePieChart = () => {
  const severityPercentage = parseFloat(getPercentage('severity').replace('%', ''));
  const frequencyPercentage = parseFloat(getPercentage('frequency').replace('%', ''));
  const criticismPercentage = parseFloat(getPercentage('criticism').replace('%', ''));

  plotPieChart(severityPercentage, frequencyPercentage, criticismPercentage);
};

// fragmento de código que llama a updatePieChart cada vez que los porcentajes cambien
watch(() => problems.value.map(item => item.severity), updatePieChart);
watch(() => problems.value.map(item => item.frequency), updatePieChart);
watch(() => problems.value.map(item => item.criticism), updatePieChart);

//fragmento de código para crear un nuevo PDF
const exportChartToPDF = async () => {
  const chartCanvas = document.getElementById('pie-chart');
  
  try {
    const pdf = new jsPDF();
    
    // fragmento de código para convertir la gráfica a imagen
    const chartImage = await html2canvas(chartCanvas);
    const chartImageData = chartImage.toDataURL('image/png');

    // fragmento de código para agregar la imagen de la gráfica al PDF
    pdf.addImage(chartImageData, 'PNG', 10, 10, 180, 150);

    // fragmento de código para crear un lienzo para la tabla
    const tableCanvas = document.createElement('canvas');
    const tableContext = tableCanvas.getContext('2d');
    const table = document.querySelector('.tablePorc');

    // fragmento de código para obtener la imagen de la tabla y ajustar el lienzo de acuerdo al tamaño de la tabla
    const tableImage = await html2canvas(table);
    tableCanvas.width = tableImage.width;
    tableCanvas.height = tableImage.height;
    
    // fragmento de código para dibujar la imagen de la tabla en el lienzo
    tableContext.drawImage(tableImage, 0, 0);

    //  fragmento de código para convertir la imagen de la tabla a formato de imagen
    const tableImageData = tableCanvas.toDataURL('image/png');
    
    // fragmento de código para agregar la imagen de la tabla al PDF debajo de la gráfica
    pdf.addImage(tableImageData, 'PNG', 10, 170, tableCanvas.width / 4, tableCanvas.height / 4);

  // fragmento de código para obtener el blob del PDF
  const pdfBlob = pdf.output('blob');
    const pdfUrl = URL.createObjectURL(pdfBlob);

    // Abre una nueva ventana con la vista previa del PDF
    window.open(pdfUrl, '_blank');
  } catch (error) {
    console.error('Error exporting chart to PDF:', error);
  }
  
};


</script>

  <template>
  <div class="container-fluid">
    <div class="row">
      <div class="col-sm-12">
        <h1>Tabla de problemas</h1>
        <h6>Se traen los Principios que se están incumpliendo, ¿De dónde salen? de la prueba que realiza el evaluador. Una vez se identifican que los problemas mostrados en la tabla son los mismos que se marcaron en la evaluación, se procede a evaluar cada uno de los problemas para hallar el nivel de usabilidad en el que está la plataforma</h6>
        <div class="container">
          <table class="table table-danger">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Descripción</th>
                <th>Heurística Incumplida</th>
                <th>Incidencias</th>
                <th>Severidad</th>
                <th>Frecuencia</th>
                <th>Criticidad</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in problems" :key="item.name">
                <td>{{ item.name }}</td>
                <td>{{ item.description }}</td>
                <td>{{ item.hi }}</td>
                <td>{{ item.incidents }}</td>
                <td>
                  <div>
                    <select class="form-select" id="severitySelect" aria-label="Severity select" v-model="item.severity">
                      <option v-for="option in options" :key="option.value" :value="option.value">{{ option.text }}</option>
                    </select>
                  </div>
                </td>
                <td>
                  <div>
                    <select class="form-select" id="frequencySelect" aria-label="Frequency select" v-model="item.frequency">
                      <option v-for="option in options" :key="option.value" :value="option.value">{{ option.text }}</option>
                    </select>
                  </div>
                </td>
                <td>{{ item.criticism = parseInt(item.severity) + parseInt(item.frequency) }}</td>
              </tr>
            </tbody>
          </table>
          <div>
            <div class="container">
              <h1>Gráficas de Porcentaje</h1>
              <div>
                <canvas id="pie-chart"></canvas>
              </div>
              <div class="tablePorc">
                <button class="btn btn-primary" @click="exportChartToPDF">Exportar gráfica a PDF</button>
                <tr>
                  <td>Nombre Columna :</td>
                  <td>Severity</td>
                  <td>Frequency</td>
                  <td>Criticism</td>
                </tr>
                <tr>
                  <td>resultado suma cada columna :</td>
                  <td>{{ getColumnSum('severity') }}</td>
                  <td>{{ getColumnSum('frequency') }}</td>
                  <td>{{ getColumnSum('criticism') }}</td>
                </tr>
                <tr>
                  <td>Percentaje a resultado suma:</td>
                  <td>{{ getPercentage('severity') }}</td>
                  <td>{{ getPercentage('frequency') }}</td>
                  <td>{{ getPercentage('criticism') }}</td>
                </tr>
                <tr>
                  <td>Recomendación:</td>
                  <td colspan="6">{{ getRecommendation() }}</td>
                </tr>
                <tr>
                  <td>Promedio Porcentaje</td>
                  <td>{{ getTotalPercentage() }}</td>
                </tr>
              </div>
              <button class="btn btn-primary" @click="saveEvaluation()">Guardar evaluación</button>
            </div>
          </div>
        </div>
      </div>
      <div class="col-sm-12">
        <h1>Evaluación de Problemas</h1>
        <div class="container">
          <h1>Escala de severidad y frecuencia</h1>
          <h6>Descripción de la tabla</h6>
          <table class="table table-warning" :style="{ width: '600px', height: '300px' }">
            <thead>
              <tr>
                <th scope="col">Nota</th>
                <th scope="col">Severidad</th>
                <th scope="col">Frecuencia</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <th scope="row">0</th>
                <td>No es un problema de usabilidad.</td>
                <td>{{ "<" }}1%</td>
              </tr>
              <tr>
                <th scope="row">1</th>
                <td>Problema "Cosmético"; no necesita ser resuelto a menos que se disponga de tiempo extra en el proyecto.</td>
                <td>1-10%</td>
              </tr>
              <tr>
                <th scope="row">2</th>
                <td>Problema de usabilidad menor: arreglarlo tiene baja prioridad.</td>
                <td>11-50%</td>
              </tr>
              <tr>
                <th scope="row">3</th>
                <td>Problema de usabilidad mayor: es importante arreglarlo.</td>
                <td>51-90%</td>
              </tr>
              <tr>
                <th scope="row">4</th>
                <td>Problema de usabilidad catastrófico: es imperativo arreglarlo antes de que el producto sea liberado.</td>
                <td>{{ ">" }}90%</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>


<!-- Estilos de la tabla que muestra los porcentajes y recomendación -->
<style>

#pie-chart {
  width: 400px;
  height: 400px;
  margin: 0 auto;
}
.tablePorc {
  width: 70%;
  border-collapse: collapse;
}

.tablePorc th,
.tablePorc td {
  border: 1px solid #dddddd;
  padding: 8px;
}

.tablePorc th {
  background-color: #f2f2f2;
  font-weight: bold;
  text-align: left;
}

.tablePorc tr:nth-child(even) {
  background-color: #f9f9f9;
}

.tablePorc tr:hover {
  background-color: #f2f2f2;
}


</style>
